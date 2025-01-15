#include "swrModel_delta.h"

#include <vector>
#include <algorithm>

#include "../hook_helper.h"
#include "../node_utils.h"

extern "C" {
#include <Swr/swrModel.h>
#include <Swr/swrAssetBuffer.h>
}

#include <globals.h>
#include <macros.h>

extern std::vector<AssetPointerToModel> asset_pointer_to_model;

// We don't have the original function decompiled properly yet
swrModel_Header *swrModel_LoadFromId_delta(MODELID id) {
    char *model_asset_pointer_begin = swrAssetBuffer_GetBuffer();
    auto header = hook_call_original(swrModel_LoadFromId, id);
    char *model_asset_pointer_end = swrAssetBuffer_GetBuffer();

    // remove all models whose asset pointer is invalid:
    std::erase_if(asset_pointer_to_model, [&](const auto &elem) {
        return elem.asset_pointer_begin >= model_asset_pointer_begin;
    });

    asset_pointer_to_model.emplace_back() = {
        model_asset_pointer_begin,
        model_asset_pointer_end,
        id,
    };

    return header;
}
