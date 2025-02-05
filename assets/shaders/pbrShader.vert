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
uniform vec3 cameraWorldPosition;

uniform int model_id;

out vec3 worldPosition;
out vec3 vReflect;
#ifdef HAS_NORMALS
out vec3 passNormal;
#endif
#ifdef HAS_TEXCOORDS
out vec2 passTexcoords;
#endif

void main()
{
    vec4 worldPos = modelMatrix * vec4(position, 1.0);
    worldPosition = vec3(worldPos.xyz) / worldPos.w;

    vec3 cameraToVertex = normalize(worldPos.xyz - cameraWorldPosition);
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * worldPos;

#ifdef HAS_NORMALS
    vec3 worldNormal = normalize(mat3(modelMatrix) * normal); // Good results but negative scale is wrong

    vReflect = reflect(cameraToVertex, worldNormal);
    passNormal = worldNormal;
#endif
#ifdef HAS_TEXCOORDS
    passTexcoords = texcoords;
#endif
}
