#version 330 core

in vec2 texcoords;

uniform float progress;

out vec4 fragColor;

void main() {
    // TODO: put a nice texture as a loading bar

    // Progress bar is computed on a [(1/3, 1/8), (2/3, 1/8 + 10px)] rectangle.
    // Later, we want to map [(0, 0), (1, 1)] rectangle back onto [(1/3, 1/8), (2/3, 1/8 + 10px)]
    const float a = 1.0 / 3.0;
    const float b = 1.0 / 8.0;
    const float c = 2.0 / 3.0;
    // original game is 480x640, and the progress bar is offset by 10 pixels.
    // Thats 1 / 48th in height
    const float width_offset = 1.0 / 48.0;
    const float d = 1.0 / 8.0 + width_offset;

    vec2 color = texcoords.xy;

    // Rectangle progress bar clipping
    if (texcoords.x < a || texcoords.x > c ||
        texcoords.y < b || texcoords.y > d) {
        color.x = 0.0;
        color.y = 0.0;
    }

    float xp = (c - a) * (progress / 100.0); // progression distance
    if (texcoords.x > (a + xp)) {
        color.x = 0.0;
        color.y = 0.0;
    }

    // magic part to map [(1/3, 1/8), (2/3, 1/8 + 10px)] rectangle back onto [(0, 0), (1, 1)]
    //                     a,   b,     c,   d                                  e, f,   g, h
    // x' = e + (x - a) * (g - e) / (c - a);
    // y' = f + (y - b) * (h - f) / (d - b);

    color.x = (color.x - 1.0 / 3.0) / (c - a);
    color.y = (color.y - 1.0 / 8.0) / width_offset;

    fragColor = vec4(color, 0.0, 1.0);
}
