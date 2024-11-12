#include "swrModel_hook.h"

#include "../hook_helper.h"
#include "../utils/node_utils.h"

#include <vector>

#include "types.h"

extern "C" {
#include <Swr/swrAssetBuffer.h>
}

extern std::vector<AssetPointerToModel> asset_pointer_to_model;

swrModel_Header *swrModel_LoadFromId_Hook(MODELID id) {
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
