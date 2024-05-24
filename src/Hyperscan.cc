#include "Hyperscan.h"
#include <iostream>

/**
 * Initialize exports
 *
 * @param env node env
 * @param exports exports object
 * @return modified exports
 */
Napi::Object HyperscanPattern::Init(Napi::Env env, Napi::Object exports) {
    const auto& match = Napi::Symbol::WellKnown(env, "match");
    const auto& replace = Napi::Symbol::WellKnown(env, "replace");

    Napi::Function func = DefineClass(env, "HyperscanPattern", {
            InstanceMethod<&HyperscanPattern::Match>(match, static_cast<napi_property_attributes>(napi_writable | napi_configurable)),
            InstanceMethod<&HyperscanPattern::Replace>(replace, static_cast<napi_property_attributes>(napi_writable | napi_configurable)),
            InstanceMethod<&HyperscanPattern::Test>("test", static_cast<napi_property_attributes>(napi_writable | napi_configurable)),
            InstanceMethod<&HyperscanPattern::ToString>("toString", static_cast<napi_property_attributes>(napi_writable | napi_configurable)),
    });

    auto* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    exports.Set("HyperscanPattern", func);

    return exports;
}

/**
 * Gets a replacement string for a match
 *
 * @param info the replacement info
 * @param match the matched substring
 * @return pair of (true, replacement string) if successful, otherwise (false, "")
 */
inline std::pair<bool, std::string> getReplacement(const replace_info& info, const std::string& match) {
    // passed javascript replacer is a function
    if (info.replacer_is_function) {
        // call function with matched string
        const auto& ret = info.replacerFunction({
			Napi::String::New(info.env, match),
			Napi::Number::New(info.env, info.last_begin)
		});

        // function errored
        if (info.env.IsExceptionPending()) return {false, ""};

        const auto& val = ret.ToString();

        // toString errored
        if (info.env.IsExceptionPending()) return {false, ""};

        return {true, val.Utf8Value()};
    }

    // passed javascript replacer is a string
    return {true, info.replacerString};
}

// add flags to pattern
bool addFlag(const std::string& input, const char flag, int32_t flagVal, std::string& flagsString, uint32_t& flags, const Napi::Env& env) {
    if (flag == -1 || flags & flagVal) {
        Napi::Error::New(env, "Invalid flags supplied to HyperscanPattern constructor '" + input + "'").ThrowAsJavaScriptException();
        return false;
    }

    flags |= flagVal;
    flagsString += flag;
    return true;
}

/**
 * Parse a flag string
 * @param input input flags
 * @param env node environment
 * @return parsed flags struct
 */
flag_info parseFlags(const std::string& input, const Napi::Env& env) {
    uint32_t flags = HS_FLAG_UTF8 | HS_FLAG_ALLOWEMPTY | HS_FLAG_SOM_LEFTMOST;
    std::string flagsString;
    bool global = false;

    for (const auto &item: input) {
        int32_t flag = -1;

        switch (item) {
            case 'i': flag = HS_FLAG_CASELESS; break;
            case 's': flag = HS_FLAG_DOTALL; break;
            case 'u': flag = HS_FLAG_UCP; break;
            case 'm': flag = HS_FLAG_MULTILINE; break;
            case 'g': {
                global = true;
                flag = 0; break;
            }
            default: break;
        }

        if (flag && !addFlag(input, item, flag, flagsString, flags, env))
            return {"", 0};
    }

    return {flagsString, flags, global};
}

/**
 * Create a new hyperscan pattern
 * @param info
 */
HyperscanPattern::HyperscanPattern(const Napi::CallbackInfo &info)
        : ObjectWrap(info) {
    std::string inputPattern;
    std::string inputFlags;

    this->scratch = nullptr;

    // passed in RegExp instance
    if (info[0].IsObject() && info[0].As<Napi::Object>().InstanceOf(info.Env().Global().Get("RegExp").As<Napi::Function>())) {
        // get pattern source
        const auto&& regexpSource = info[0].As<Napi::Object>().Get("source").ToString();

        if (info.Env().IsExceptionPending())
            return;

        // get pattern flags
        const auto&& regexpFlags = info[0].As<Napi::Object>().Get("flags").ToString();
        if (info.Env().IsExceptionPending())
            return;

        inputFlags = regexpFlags.Utf8Value();
        inputPattern = regexpSource.Utf8Value();
    } else if (info.Length() > 0) {
        // get pattern from first argument
        const auto& first = info[0].ToString();
        if (info.Env().IsExceptionPending())
            return;

        inputPattern = first.Utf8Value();

        // get flags from second argument
        if (info.Length() > 1) {
            const auto& second = info[1].ToString();

            if (info.Env().IsExceptionPending())
                return;

            inputFlags = second.Utf8Value();
        }
    } else {
        // no arguments, default pattern
        inputPattern = "(?:)";
    }

    // parse flag string
    const auto& parsedFlags = parseFlags(inputFlags, info.Env());
    this->flagsString = parsedFlags.flagsString;
    this->flags = parsedFlags.flags;
    this->global = parsedFlags.global; // global mode is emulated since hyperscan does not support global
    this->source = inputPattern;

    // compile the pattern
    hs_database_t* db;
    hs_compile_error_t* error;
    hs_error_t result = hs_compile(inputPattern.c_str(), parsedFlags.flags, HS_MODE_BLOCK, nullptr, &db, &error);

    // pattern parse error
    if (result != HS_SUCCESS) {
        Napi::Error::New(info.Env(), std::string("Invalid regular expression: /") + inputPattern + "/" + flagsString + ": " + error->message).ThrowAsJavaScriptException();
        return;
    }

    // allocate scratch space
    result = hs_alloc_scratch(db, &this->scratch);

    if (result != HS_SUCCESS) {
        Napi::Error::New(info.Env(), "Failed to allocate scratch space for pattern").ThrowAsJavaScriptException();
        return;
    }

    this->database = db;
}

/**
 * Test if a pattern matches a string
 * @param info
 * @return Napi::Boolean of test status
 */
Napi::Value HyperscanPattern::Test(const Napi::CallbackInfo &info) {
    const auto& input =  info[0].ToString();

    if (info.Env().IsExceptionPending())
        return info.Env().Null();

    const auto& val = input.Utf8Value();

    bool found = false;

    // scan string
    hs_scan(this->database, val.c_str(), val.length(), 0, this->scratch,
            [](uint32_t, uint64_t, uint64_t, uint32_t, void* context) {
        // store match status and return 1 to stop matching
        bool* found = static_cast<bool*>(context);
        *found = true;
        return 1;
    }, &found);

    return Napi::Boolean::New(info.Env(), found);
}

/**
 * Match a pattern against a string
 * @param info
 * @return Napi::Array of matches
 */
Napi::Value HyperscanPattern::Match(const Napi::CallbackInfo &info) {
    const auto& val = info[0].ToString();

    if (info.Env().IsExceptionPending())
        return info.Env().Null();

    const auto& input = val.Utf8Value();

    auto output = Napi::Array::New(info.Env());

    match_info matchInfo = {info.Env(), this->global, 0, 0, true, input, output, 0};

    // scan string
    hs_scan(this->database, input.c_str(), input.length(), 0, this->scratch, [](uint32_t id, uint64_t from, uint64_t to, uint32_t, void* context) {
        auto info = static_cast<match_info*>(context);

        // first match, set values
        if (info->initial) {
            info->last_begin = from;
            info->last_end = to;
            info->initial = false;
            return (int) !info->global; // if global, continue matching
        }

        // new match started, store previous match substring
        if (info->last_begin != from)
            info->output.Set(info->index++, Napi::String::New(info->env, info->input.substr(info->last_begin, info->last_end - info->last_begin)));

        // reset last index values
        info->last_begin = from;
        info->last_end = to;

        return (int) !info->global; // if global, continue matching
    }, &matchInfo);

    // if more than one match, store result of last match
    if (!matchInfo.initial) {
        matchInfo.output.Set(matchInfo.index, Napi::String::New(matchInfo.env, matchInfo.input.substr(matchInfo.last_begin,
                                                                     matchInfo.last_end -
                                                                     matchInfo.last_begin)));
    } else { // no match, return null
        return info.Env().Null();
    }

    return matchInfo.output;
}

/**
 * Replace string using given pattern
 * @param info
 * @return Napi::String of replaced string
 */
Napi::Value HyperscanPattern::Replace(const Napi::CallbackInfo &info) {
    const auto& val = info[0].ToString();

    if (info.Env().IsExceptionPending())
        return info.Env().Null();

    const auto& input = val.Utf8Value();

    replace_info replaceInfo = {info.Env(), this->global, 0, 0, true, input, "", false};
    replaceInfo.replace_error = false;

    // passed replacer is a function
    if (info[1].IsFunction()) {
        replaceInfo.replacer_is_function = true;
        replaceInfo.replacerFunction = info[1].As<Napi::Function>();
    } else { // passed replacer is assumed a string
        const auto& replacer = info[1].ToString();

        if (info.Env().IsExceptionPending())
            return info.Env().Null();

        replaceInfo.replacerString = replacer.Utf8Value();
    }

    if (hs_scan(this->database, input.c_str(), input.length(), 0, this->scratch, [](uint32_t id, uint64_t from, uint64_t to, uint32_t, void* context) {
        auto info = static_cast<replace_info*>(context);

        // first match, set values
        if (info->initial) {
            if (from > 0)
                info->output += info->input.substr(0, from); // add prefix string before initial match to output

            info->last_begin = from;
            info->last_end = to;
            info->initial = false;
            return (int) !info->global; // if global, continue matching
        }

        // new match started, store previous match replacement
        if (info->last_begin != from) {
            const auto len = from - info->last_end;
            // get replacement for match
            const auto& replacer = getReplacement(*info, info->input.substr(info->last_begin, info->last_end - info->last_begin));

            if (!replacer.first) {
                // replacer errored
                info->replace_error = true;
                return 1;
            }

            // add replaced string
            info->output += replacer.second;

            // add string between previous match and current match
            if (len > 0)
                info->output += info->input.substr(info->last_end, len);
        }

        // reset values
        info->last_begin = from;
        info->last_end = to;

        return (int) !info->global; // if global, continue matching
    }, &replaceInfo) != HS_SUCCESS && replaceInfo.replace_error) return info.Env().Null();

    // more than one match, add result of replacement for last match
    if (!replaceInfo.initial) {
        const auto& replacer = getReplacement(replaceInfo, replaceInfo.input.substr(replaceInfo.last_begin,
                                                                                    replaceInfo.last_end -
                                                                                    replaceInfo.last_begin));
        if (!replacer.first) return info.Env().Null();

        replaceInfo.output += replacer.second;
    }

    replaceInfo.output += replaceInfo.input.substr(replaceInfo.last_end);

    return Napi::String::New(info.Env(), replaceInfo.output);
}

HyperscanPattern::~HyperscanPattern() {
    // delete database and scratch
    if (this->database)
        hs_free_database(this->database);
    if (this->scratch)
        hs_free_scratch(this->scratch);
}

Napi::Value HyperscanPattern::ToString(const Napi::CallbackInfo &info) {
    return Napi::String::New(info.Env(), "/" + this->source + "/g" + this->flagsString);
}
