; nasm -fwin32 hello.asm && gcc hello.obj -o hello.exe && objdump -d hello.exe --no-addresses --start-address=0x4014f0 --stop-address=0x401800 > dump.txt

    global  _main
    extern  _printf

    section .text

_main:
    push ebp
    mov ebp, esp

    ; variables
    sub esp, 30h
    xor eax, eax
	; mov [ebp - 04h], eax			; will store number of exported functions
	; mov [ebp - 08h], eax			; will store address of exported functions addresses table
	; mov [ebp - 0ch], eax			; will store address of exported functions name table
	; mov [ebp - 10h], eax			; will store address of exported functions ordinal table
    ; mov [ebp - 14h], eax ; LoadLibraryA 0
    mov [ebp - 18h], eax ; LoadLibraryA VA

    ; mov [ebp - 1ch], eax ; GetProcAddress 0
    mov [ebp - 20h], eax ; GetProcAddress VA

    ; mov [ebp - 24h], eax ; swr_reimpl.dll 0
    ; mov [ebp - 28h], eax ; hook_init_win 0
    ; mov [ebp - 2ch], eax ; counter for loop
	mov [ebp - 30h], eax			; reserved

    ; push swr_reimpl.dll 0 to stack
    push 00006c6ch
    nop
    nop
    nop
    jmp $+6
    nop
    nop
    nop
    nop
    push 642e6c70h
    nop
    jmp $+6
    nop
    nop
    nop
    nop
    push 6d696572h
    push 5f727773h
    mov [ebp - 24h], esp

    ; push hook_init_win 0 to stack
    push 0000006eh
    push 69775F74h
    push 696e695fh
    push 6b6f6f68h
    mov [ebp - 28h], esp

    ; push LoadLibraryA 0 to stack
    push 00000000h
    jmp $+6
    nop
    nop
    nop
    nop
    push 41797261h
    push 7262694ch
    push 64616f4ch

    ; push GetProcAddress 0 to stack
    nop
    jmp $+6
    nop
    nop
    nop
    nop
    mov [ebp - 14h], esp
    push 00007373h
    push 65726464h
    push 41636f72h
    push 50746547h
    mov [ebp - 1ch], esp

	; get kernel32 base address
	mov eax, [fs:30h]		    	; Pointer to PEB (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
	mov eax, [eax + 0ch]			; Pointer to Ldr
	mov eax, [eax + 14h]			; Pointer to InMemoryOrderModuleList
	mov eax, [eax]				  	; this program's module
	mov eax, [eax]  					; ntdll module
	mov eax, [eax -8h + 18h]	; kernel32.DllBase

	; kernel32 base address
	mov ebx, eax							; store kernel32.dll base address in ebx

	; get address of PE signature
	mov eax, [ebx + 3ch]			; 0x3c into the image - RVA of PE signature
	add eax, ebx				    	; address of PE signature: eax = eax + kernel32 base -> eax = 0xf8 + kernel32 base

	; get address of Export Table
	mov eax, [eax + 78h]			; 0x78 bytes after the PE signature is an RVA of Export Table
	add eax, ebx					    ; address of Export Table = Export Table RVA + kernel32 base

	; get number of exported functions
	mov ecx, [eax + 14h]

	mov [ebp - 4h], ecx				; store number of exported functions

	; get address of exported functions table
	mov ecx, [eax + 1ch]			; get RVA of exported functions table
	add ecx, ebx				    	; get address of exported functions table
	mov [ebp - 8h], ecx				; store address of exported functions table

	; get address of name pointer table
	mov ecx, [eax + 20h]			; get RVA of Name Pointer Table
	add ecx, ebx					    ; get address of Name Pointer jTable
    nop
    jmp $+6
    nop
    nop
    nop
    nop
	mov [ebp - 0ch], ecx			; store address of Name Pointer Table

	; get address of functions ordinal table
	mov ecx, [eax + 24h]			; get RVA of functions ordinal table
	add ecx, ebx					    ; get address of functions ordinal table
	mov [ebp - 10h], ecx			; store address of functions ordinal table

    ; loop through exported function name pointer table and find position for both LoadLibraryA and GetProcAddress
	xor eax, eax
    jmp $+6
    nop
    nop
    nop
    nop
	cld											; https://en.wikipedia.org/wiki/Direction_flag

FindFunctions:
    ; setup params
    mov esi, [ebp - 14h] ; "LoadLibraryA"
    mov ecx, 13
    call GetFunctionVA
    jnz FindLoadLibraryA
    mov [ebp - 18h], edx  ; store LoadLibraryA VA
FindLoadLibraryA:
    ; setup params
    mov esi, [ebp - 1ch]; "GetProcAddress"
    mov ecx, 15
    call GetFunctionVA
    jnz FindGetProcAddress
    mov [ebp - 20h], edx  ; store GetProcAddress VA
FindGetProcAddress:

	inc eax									; increase the counter
	cmp eax, [ebp - 4h]			; check if we have looped over all the exported function names
    jmp $+6
    nop
    nop
    nop
    nop
	jne FindFunctions

    ; Finally, our call to hook_win_init
    mov ecx, [ebp - 24h]
    push ecx
    mov eax, [ebp - 18h]  ; get LoadLibrary VA
	call eax 			  ; call LoadLibraryA

    mov ecx, [ebp - 28h]
    push ecx
    push eax
    nop
    jmp $+6
    nop
    nop
    nop
    nop
    mov eax, [ebp - 20h]    ; get GetProcAddress VA from variable
    call eax                ; call GetProcAddress

    call eax ; call hook_win_init
    ; clear stack better than this ?
    mov esp, ebp
    pop ebp
    ret

GetFunctionVA:
    ; param eax counter, pointer to function name esi: string, ecx: string len return edx

	mov edi, [ebp - 0ch]		; edi = pointer to exported function names table
	mov edi, [edi + eax*4]	; get RVA of the next function name in the exported function names table
	add edi, ebx				    ; get address of the next function name in the exported function names table

	repe cmpsb					    ; check if esi == edi
    ; save counter
	jnz GetFunctionVAEnd
    nop
    jmp $+6
    nop
    nop
    nop
    nop

    mov [ebp - 2ch], eax
	mov ecx, [ebp - 10h]		; ecx = ordinal table
	mov edx, [ebp - 8h]			; edx = export address table
    nop
    jmp $+6
    nop
    nop
    nop
    nop

	mov ax, [ecx + eax * 2]	; get LoadLibraryA ordinal
	mov eax, [edx + eax * 4]; get RVA of LoadLibraryA function
	add eax, ebx				    ; get VA of LoadLibraryA
    mov edx, eax
    ; restore counter
    mov eax, [ebp - 2ch]
    cmp eax, eax ; flip ZF to 1
GetFunctionVAEnd:
    ret
