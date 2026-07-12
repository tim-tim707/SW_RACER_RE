#version 330 core

layout(location = 0) in vec3 position;
layout(location = 1) in vec4 color;
layout(location = 2) in vec2 uv;
layout(location = 3) in vec3 normal;

out vec4 passColor;
out vec2 passUV;
out vec3 passNormal;
out float passZ;

uniform float nearPlane;
uniform mat4 projMatrix;
uniform mat4 viewMatrix;
uniform mat4 modelMatrix;
uniform vec2 uvOffset;
uniform vec2 uvScale;

// N64 texture-coordinate generation (issue #206). The N64 had a G_TEXTURE_GEN geometry
// mode that generated texture coords at runtime from the vertex normal, producing the
// pseudo-reflective "chrome" look (Ark cockpit, Fud Sang engines, traction green,
// Vengeance fans) that slides across the surface as the pod turns. The PC port baked
// static UVs and dropped the mode entirely, so we re-generate it here for the meshes the
// renderer tags as reflective. 0 = use the baked UVs, 1 = generate sphere-map UVs.
uniform int texgenMode;
// Scales the generated coords about the texture centre. 1.0 = plain normal->UV mapping; higher
// spreads more of the reflection texture across the surface (more detail / higher contrast), for
// tuning the effect toward the N64 look.
uniform float texgenScale;
// Rotates the generated coords about the texture centre (radians) -- spins the reflection.
uniform float texgenRotation;
// Pans the generated coords (added to the UV) -- shifts which part of the reflection texture lands
// on the surface, for aligning the reflection position with the N64.
uniform vec2 texgenOffset;

void main() {
    vec4 posView = viewMatrix * modelMatrix * vec4(position, 1);
    gl_Position = projMatrix * posView;
    passColor = color;
    if (texgenMode != 0) {
        // Faithful G_TEXTURE_GEN: coords come from the view-space normal, so a normal
        // facing the camera lands at the texture centre and the mapping rotates with the
        // surface. The normal arrives in world space (modelMatrix is identity in the mesh
        // draw path -- vertices/normals are pre-transformed on the CPU), so rotate it into
        // view space here. The result is already normalized to [0,1]; the baked
        // uvScale/uvOffset tiling does not apply to generated coords.
        vec3 nv = normalize(mat3(viewMatrix) * normal);
        float cr = cos(texgenRotation);
        float sr = sin(texgenRotation);
        vec2 g = vec2(nv.x * cr - nv.y * sr, nv.x * sr + nv.y * cr);
        passUV = g * 0.5 * texgenScale + 0.5 + texgenOffset;
    } else {
        passUV = uv / (uvScale * 4096.0) + uvOffset;
    }
    passNormal = normalize(transpose(inverse(mat3(modelMatrix))) * normal);
    passZ = -posView.z;
}
