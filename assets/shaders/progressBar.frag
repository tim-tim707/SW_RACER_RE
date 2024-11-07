#version 420

in vec2 texcoords;

uniform float progress;

layout(binding = 0) uniform sampler2D beamTexture;

out vec4 fragColor;

void main()
{
    // Progress bar is computed on a [(1/3, 1/8), (2/3, 1/8 + 10px)] rectangle.
    // Later, we want to map [(0, 0), (1, 1)] rectangle back onto [(1/3, 1/8), (2/3, 1/8 + 10px)]

    // Edit: The original values are not big enough to enjoy the beam texture, so we modify them slightly
    // const float x1 = 1.0 / 3.0;
    const float x1 = 1.0 / 8.0;
    const float y1 = 1.0 / 8.0;
    // const float x2 = 2.0 / 3.0;
    const float x2 = 1.0 - x1;

    // original game is 480x640, and the progress bar is offset by 10 pixels.
    // Thats 1 / 48th in height

    // Edit: beam texture is 64*16 which is 4:1 ratio
    // const float height_offset = 1.0 / 48.0;
    const float height_offset = 1.0 / 8.0;
    const float y2 = y1 + height_offset;

    vec2 beamTexCoords = texcoords.xy;

    // Rectangle progress bar clipping
    if (texcoords.x < x1 || texcoords.x > x2 || texcoords.y < y1 || texcoords.y > y2)
    {
        beamTexCoords.x = 0.0;
        beamTexCoords.y = 0.0;
    }

    float xp = (x2 - x1) * (progress / 100.0); // progression distance
    if (texcoords.x > (x1 + xp))
    {
        beamTexCoords.x = 0.0;
        beamTexCoords.y = 0.0;
    }

    // magic part to map [(1/3, 1/8), (2/3, 1/8 + 10px)] rectangle back onto [(0, 0), (1, 1)]
    //                     x1,   y1,    x2,   y2                               e, f,   g, h
    // x' = e + (x - x1) * (g - e) / (x2 - x1);
    // y' = f + (y - y1) * (h - f) / (y2 - y1);

    beamTexCoords.x = (beamTexCoords.x - x1) / (x2 - x1);
    beamTexCoords.y = (beamTexCoords.y - y1) / height_offset;

    if (beamTexCoords.x < 0.0 && beamTexCoords.y < 0.0)
    {
        fragColor = vec4(0.0, 0.0, 0.0, 1.0);
    }
    else
    {
        fragColor = texture(beamTexture, beamTexCoords);
    }
}
