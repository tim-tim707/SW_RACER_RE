#version 330 core

in vec2 texcoords;

uniform sampler2D tex;

out vec4 fragColor;

void main() {
    fragColor = texture(tex, vec2(texcoords.s, 1.0 - texcoords.t)); // horizontal flip
}
