// Taken from https://github.com/KhronosGroup/glTF-Sample-Renderer

layout(location = 0) in vec3 position;
#ifdef HAS_NORMALS
layout(location = 1) in vec3 normal;
#endif
#ifdef HAS_TEXCOORDS
layout(location = 2) in vec2 texcoords;
#endif
#ifdef HAS_VERTEXCOLOR // only vec3 for the moment
layout(location = 3) in vec3 vertexColor;
#endif
#ifdef HAS_WEIGHTS
layout(location = 4) in vec4 weights;
#endif
#ifdef HAS_JOINTS
layout(location = 5) in vec4 joints;
#endif

#ifdef HAS_SKINNING
layout(std430, binding = 7) readonly buffer jointMatricesBuffer
{
    mat4 jointMatrices[];
};
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
#ifdef HAS_VERTEXCOLOR
out vec3 passVertexColor;
#endif

#ifdef HAS_SKINNING
mat4 getSkinningMatrix() {
    mat4 skin = mat4(0);

#if defined(HAS_WEIGHTS) && defined(HAS_JOINTS)
    skin +=
        weights.x * jointMatrices[int(joints.x) * 2] +
        weights.y * jointMatrices[int(joints.y) * 2] +
        weights.z * jointMatrices[int(joints.z) * 2] +
        weights.w * jointMatrices[int(joints.w) * 2];
#endif

    if (skin == mat4(0)) {
        return mat4(1);
    }
    return skin;
}

mat4 getSkinningNormalMatrix() {
    mat4 skin = mat4(0);

#if defined(HAS_WEIGHTS) && defined(HAS_JOINTS)
    skin +=
        weights.x * jointMatrices[int(joints.x) * 2 + 1] +
        weights.y * jointMatrices[int(joints.y) * 2 + 1] +
        weights.z * jointMatrices[int(joints.z) * 2 + 1] +
        weights.w * jointMatrices[int(joints.w) * 2 + 1];
#endif

    if (skin == mat4(0)) {
        return mat4(1);
    }
    return skin;
}
#endif // HAS_SKINNING

vec4 getPosition() {
    vec4 pos = vec4(position, 1.0);

#ifdef HAS_SKINNING
    pos += getSkinningMatrix() * pos;
#endif

    return pos;
}

#ifdef HAS_NORMALS
vec3 getNormal() {
    vec3 normal_ = normal;

#ifdef HAS_SKINNING
    normal_ += mat3(getSkinningNormalMatrix()) * normal_;
#endif

    return normal_;
}
#endif // HAS_NORMALS

void main()
{
    vec4 worldPos = modelMatrix * getPosition();
    worldPosition = vec3(worldPos.xyz) / worldPos.w;

    vec3 cameraToVertex = normalize(worldPos.xyz - cameraWorldPosition);
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * worldPos;

#ifdef HAS_NORMALS
    vec3 worldNormal = normalize(mat3(modelMatrix) * getNormal()); // Good results but negative scale is wrong

    vReflect = reflect(cameraToVertex, worldNormal);
    passNormal = worldNormal;
#endif
#ifdef HAS_TEXCOORDS
    passTexcoords = texcoords;
#endif
#ifdef HAS_VERTEXCOLOR
    passVertexColor = vertexColor;
#endif
}
