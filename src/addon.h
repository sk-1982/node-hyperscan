#ifndef HYPERSCAN_ADDON_H
#define HYPERSCAN_ADDON_H

#include "hs.h"
#include "napi.h"

class HyperscanAddon : public Napi::Addon<HyperscanAddon> {
public:
    HyperscanAddon(Napi::Env env, Napi::Object exports);
};

#endif //HYPERSCAN_ADDON_H
