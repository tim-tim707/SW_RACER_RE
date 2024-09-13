#include "gltf_utils.h"

// Define these only in *one* .cc file.
#define TINYGLTF_IMPLEMENTATION
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define TINYGLTF_NOEXCEPTION// optional. disable exception handling.
#include "tiny_gltf.h"

extern "C" FILE *hook_log;

void init_tinygltf() {
    fprintf(hook_log, "[init_tinygltf]\n");
    tinygltf::Model model;
    tinygltf::TinyGLTF loader;
    std::string err;
    std::string warn;

    std::string filename = "toto.gltf";
    bool ret = loader.LoadASCIIFromFile(&model, &err, &warn, filename);
    //bool ret = loader.LoadBinaryFromFile(&model, &err, &warn, argv[1]); // for binary glTF(.glb)

    if (!warn.empty()) {
        fprintf(hook_log, "Warn: %s\n", warn.c_str());
    }

    if (!err.empty()) {
        fprintf(hook_log, "Err: %s\n", err.c_str());
    }

    if (!ret) {
        fprintf(hook_log, "Failed to parse glTF\n");
    }

    fflush(hook_log);
}
