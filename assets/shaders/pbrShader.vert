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

// From Inigo Quilez 2019: https://www.shadertoy.com/view/3s33zj
// https://github.com/graphitemaster/normals_revisited
mat3 adjoint(in mat4 m)
{
    // 3 alternative ways to write the same thing

    return mat3(cross(m[1].xyz, m[2].xyz), cross(m[2].xyz, m[0].xyz), cross(m[0].xyz, m[1].xyz));
}

vec3 inverseTransformDirection( in vec3 dir, in mat4 matrix ) {
    return normalize( ( vec4( dir, 0.0 ) * matrix ).xyz );
}

void main()
{
    vec4 worldPos = modelMatrix * vec4(position, 1.0);
    worldPosition = vec3(worldPos.xyz) / worldPos.w;

    mat3 normalMatrix = mat3(viewMatrix * modelMatrix);
    vec3 cameraToVertex = normalize(worldPos.xyz - cameraWorldPosition);
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * worldPos;

#ifdef HAS_NORMALS
    vec3 transformedNormal = normalMatrix * normal;
    vec3 worldNormal = inverseTransformDirection(transformedNormal, viewMatrix);
    // dir * viewMatrix
    // (viewMatrix * modelMatrix * normal) * viewMatrix
    //   - inverse(mat3(viewMatrix)) <=> transpose(mat3(viewMatrix))
    // inverse(mat3(viewMatrix)) * viewMatrix * modelMatrix * normal = worldNormal

    worldNormal = mat3(modelMatrix) * normal; // Good results but negative scale is wrong
    // worldNormal = adjoint(modelMatrix) * normal; // fixes negative scale but handness is wrong ?

    vReflect = reflect(cameraToVertex, worldNormal);
    passNormal = worldNormal;
#endif
#ifdef HAS_TEXCOORDS
    passTexcoords = texcoords;
#endif
}
