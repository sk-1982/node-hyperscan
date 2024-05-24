#include "hs.h"
#include "napi.h"
#include "addon.h"
#include "Hyperscan.h"

HyperscanAddon::HyperscanAddon(Napi::Env env, Napi::Object exports) {
    HyperscanPattern::Init(env, exports);
}

NODE_API_ADDON(HyperscanAddon)
