#version 330 core

in vec4 passColor;
in vec2 passUV;

out vec4 outColor;

uniform sampler2D tex;
uniform bool isSDF;

void main() {
    if (isSDF) {
        // Signed-distance-field glyph page: edge at 0.5, screen-space antialiased.
        float dist = texture(tex, passUV).r;
        float w = fwidth(dist);
        float alpha = smoothstep(0.5 - w, 0.5 + w, dist);
        outColor = vec4(passColor.rgb, passColor.a * alpha);
    } else {
        vec4 texel = texture(tex, passUV);
        outColor = texel * passColor;
    }
}
