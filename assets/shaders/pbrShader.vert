// Taken from https://github.com/KhronosGroup/glTF-Sample-Renderer

layout(location = 0) in vec3 position;
#ifdef HAS_NORMALS
layout(location = 1) in vec3 normal;
#endif
#ifdef HAS_TEXCOORDS
layout(location = 2) in vec2 texcoords;
#endif

uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;

uniform int model_id;

out vec3 worldPosition;
#ifdef HAS_NORMALS
out vec3 passNormal;
#endif
#ifdef HAS_TEXCOORDS
out vec2 passTexcoords;
#endif

void main()
{
    vec4 pos = modelMatrix * vec4(position, 1.0);
    worldPosition = vec3(pos.xyz) / pos.w;

    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * pos;

#ifdef HAS_NORMALS
    passNormal = normalize(normal);
    // TODO: remove this if ibl is working with rotation
    // passNormal = normalize(transpose(inverse(mat3(modelMatrix))) * normal);
#endif
#ifdef HAS_TEXCOORDS
    passTexcoords = texcoords;
#endif
}
