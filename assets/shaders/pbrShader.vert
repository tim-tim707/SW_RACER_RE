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
    vec4 pos = modelMatrix * vec4(position, 1.0);
    worldPosition = vec3(pos.xyz) / pos.w;

    vec4 worldPosition4 = modelMatrix * vec4(position, 1.0);
    mat3 normalMatrix = mat3(viewMatrix * modelMatrix);
    vec3 cameraToVertex = normalize(worldPosition4.xyz - cameraWorldPosition);
    // Yes, precomputing modelView is better and we should do it
    gl_Position = projMatrix * viewMatrix * pos;

#ifdef HAS_NORMALS
    vec3 transformedNormal = normalMatrix * normal;
    vec3 worldNormal = inverseTransformDirection(transformedNormal, viewMatrix);
    vReflect = reflect(cameraToVertex, worldNormal);

    // world2object is transpose(inverse(modelMatrix));
    // float3 worldNormal = mul( float4( v.normal, 0.0 ), _World2Object ).xyz; // against model matrix scaling

    // passNormal = normalize(transpose(inverse(mat3(modelMatrix))) * normal);
    // passNormal = normalize(adjoint(modelMatrix) * normal);
    passNormal = worldNormal;
    // passNormal = adjoint(objectToWorld) * (inverse(objectToWorld) * vec4(pos, 1.0)).xyz;
    // 3JS: normal = inverseTransformDirection(transpose(inverse(modelView)), view);
#endif
#ifdef HAS_TEXCOORDS
    passTexcoords = texcoords;
#endif
}
