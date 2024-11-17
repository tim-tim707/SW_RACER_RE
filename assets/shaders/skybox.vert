#version 330 core

layout(location = 0) in vec3 aPos;

out vec3 TexCoords;

uniform mat4 projMatrix;
uniform mat4 viewMatrix;

void main()
{
    TexCoords = -aPos;
    mat3 view_noTranslation = mat3(viewMatrix);
    vec4 pos = projMatrix * mat4(vec4(view_noTranslation[0], 0), vec4(view_noTranslation[1], 0), vec4(view_noTranslation[2], 0), vec4(0, 0, 0, 1)) * vec4(aPos, 1.0);
    gl_Position = pos.xyww;
}
