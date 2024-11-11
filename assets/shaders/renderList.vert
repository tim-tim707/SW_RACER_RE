#version 330 core

layout(location = 0) in vec4 position;
layout(location = 1) in vec4 color;
layout(location = 2) in vec2 uv;

out vec4 passColor;
out vec2 passUV;

uniform mat4 projMatrix;

void main() {
    vec4 posView = position;
    gl_Position = projMatrix * posView;

    passColor = color;
    passUV = uv;
}
