#ifndef HYPERSCAN_HYPERSCAN_H
#define HYPERSCAN_HYPERSCAN_H

#include <cstdint>
#include <vector>

#include "napi.h"
#include "hs.h"
#include "addon.h"

typedef struct match_info {
    const Napi::Env& env;
    bool global;
    uint64_t last_begin;
    uint64_t last_end;
    bool initial;
    const std::string& input;
    Napi::Array& output;
    int index;
} match_info;

typedef struct replace_info {
    const Napi::Env& env;
    bool global;
    uint64_t last_begin;
    uint64_t last_end;
    bool initial;
    const std::string& input;
    std::string output;
    bool replacer_is_function;
    Napi::Function replacerFunction;
    std::string replacerString;
    bool replace_error;
} replace_info;

typedef struct flag_info {
    std::string flagsString;
    uint32_t flags;
    bool global;
} flag_info;

class HyperscanPattern : public Napi::ObjectWrap<HyperscanPattern> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    explicit HyperscanPattern(const Napi::CallbackInfo &info);
    ~HyperscanPattern();
private:
    Napi::Value Match(const Napi::CallbackInfo& info);
    Napi::Value Replace(const Napi::CallbackInfo& info);
    Napi::Value Test(const Napi::CallbackInfo& info);
    Napi::Value ToString(const Napi::CallbackInfo& info);
    hs_scratch_t* scratch;

    std::string source;
    std::string flagsString;
    uint32_t flags = 0;
    bool global;
    hs_database_t* database = nullptr;
};

#endif //HYPERSCAN_HYPERSCAN_H
