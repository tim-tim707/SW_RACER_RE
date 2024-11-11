#version 330 core

in vec4 passColor;
in vec2 passUV;

out vec4 outColor;

uniform sampler2D tex;

void main() {
    vec4 texel = texture(tex, passUV);
    outColor = texel * passColor;
}
