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

void main() {
    vec4 posView = viewMatrix * modelMatrix * vec4(position, 1);
    gl_Position = projMatrix * posView;
    passColor = color;
    passUV = uv / (uvScale * 4096.0) + uvOffset;
    passNormal = normalize(transpose(inverse(mat3(modelMatrix))) * normal);
    passZ = -posView.z;
}
