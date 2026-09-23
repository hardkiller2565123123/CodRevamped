option casemap:none

EXTERN g_FloatProbeOriginal1:QWORD
EXTERN g_FloatProbeOriginal2:QWORD
EXTERN g_FloatProbeOriginal3:QWORD
EXTERN FloatProbeRecord1:PROC
EXTERN FloatProbeRecord2:PROC
EXTERN FloatProbeRecord3:PROC

PROBE_BODY MACRO recorder, original
    sub rsp, 0C8h
    mov [rsp+20h], rcx
    mov [rsp+28h], rdx
    mov [rsp+30h], r8
    mov [rsp+38h], r9
    mov [rsp+40h], rax
    mov [rsp+48h], r10
    mov [rsp+50h], r11
    mov rax, [rsp+0C8h]
    mov [rsp+58h], rax
    movups [rsp+60h], xmm0
    movups [rsp+70h], xmm1
    movups [rsp+80h], xmm2
    movups [rsp+90h], xmm3
    movups [rsp+0A0h], xmm4
    movups [rsp+0B0h], xmm5
    lea rax, [rsp+0C8h]
    mov [rsp+0C0h], rax
    lea rcx, [rsp+20h]
    call recorder
    mov rcx, [rsp+20h]
    mov rdx, [rsp+28h]
    mov r8,  [rsp+30h]
    mov r9,  [rsp+38h]
    mov rax, [rsp+40h]
    mov r10, [rsp+48h]
    mov r11, [rsp+50h]
    movups xmm0, [rsp+60h]
    movups xmm1, [rsp+70h]
    movups xmm2, [rsp+80h]
    movups xmm3, [rsp+90h]
    movups xmm4, [rsp+0A0h]
    movups xmm5, [rsp+0B0h]
    add rsp, 0C8h
    jmp qword ptr [original]
ENDM

PUBLIC FloatProbeDetour1
PUBLIC FloatProbeDetour2
PUBLIC FloatProbeDetour3

.code
FloatProbeDetour1 PROC
    PROBE_BODY FloatProbeRecord1, g_FloatProbeOriginal1
FloatProbeDetour1 ENDP

FloatProbeDetour2 PROC
    PROBE_BODY FloatProbeRecord2, g_FloatProbeOriginal2
FloatProbeDetour2 ENDP

FloatProbeDetour3 PROC
    PROBE_BODY FloatProbeRecord3, g_FloatProbeOriginal3
FloatProbeDetour3 ENDP
END
