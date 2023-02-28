There is a cracking description available by FiX which documents the CD check behaviour:

```
Free Information Xchange presents:

Star Wars Episode 1 Racer - CD crack by Static Vengeance - May 26th, 1999

REQUIREMENTS:
Full game install
W32Dasm & Hex editor

	With all the hype about the new Star Wars movie (episode 1) you just knew there were going to be
games based on it.  Star Wars Episode 1 Racer is just such a game.  The game requires a 3D accelerator
and makes good use of it as well!  With dual voodoo 2 cards the game looks fantasic and with all the 
options turned on (or on high) runs quit fast.  The cut scenes are very good and the game play is great
so this game is well worth the money to buy.  I just have two minor problems with this racer.  First, once
you've seen the animations (cut scene movies) you really don't need to seem them every time you play the
game.  Second is a little program bug so commonly found in todays games, and that is the copy protection
used.  Why do they always make you have the original CD in the drive just to play the darn game?  Like any
game you'll be playing alot you don't want to hunt down the original CD to play it.  Also if you have kids
you'll want to make sure the CD is protected from harm.  The best way to do that is not to have the game
require the CD!  With a little effort on your part and a little guidance on my part you'll be able to do
that with this game.
	If you install the game and run it you'll notice that you'll need to put the CD in the drive.  One
of the reasons this is needed is due to the fact that the music files and all of the animations are kept on
the CD to keep the game install size down.  Fair enough, but what if we kill the animations and copy the
music files to the hard drive?  Then we can track down the CD check and kill that as well.  We'll end up with
a cracked copy of the game we can play anytime without the need for the CD to be in the CD Rom drive.  So let's
get started on our quest.  Install the game and you'll see two exe files.  The first one is basicly a loader,
but it has some very important features.  When you first run the game it's the file racer.exe that let's you
choose your 3D card and resolution.  Otherwise you're limited the stock 640x480 @ 16 bit color.  Hey!, we've
got big monitors and high powered 3D cards and we want to use higher res, right?  So we'll need to kill the
CD check in that file.  The other file is of course the main game program called swep1rcr.exe and we'll need
to track down the CD check in that file as well.  So disassemble racer.exe and do the usual trick:
  Go up to the menu bar and select "Refs" and then "String Data Refs" from the drop down menu.  When the refs
pop-up box comes up, grab the slider bar and start scrolling down looking for anything that looks interesting.
Eventualy, if you're paying attention, you'll find a ref of "/LNCH099/Please insert the CD "  Double click on
that and you'll be put in the middle of some routine.  However this string comes up 3 times so you'll have to
look at the surounding code to see which one is the one that is the CD check.  So checking around a bit with
the second occurrance you'll see some interesting things:

  -- Program Code --
:00404856 8D95F0FEFFFF            lea edx, dword ptr [ebp+FFFFFEF0]
:0040485C 52                      push edx
:0040485D E8BE7D0000              call 0040C620
:00404862 83C408                  add esp, 00000008

* Possible StringData Ref from Data Obj ->"Star Wars: Episode I Racer\"
                                  |
:00404865 68ACCC4200              push 0042CCAC
:0040486A 8D85F0FEFFFF            lea eax, dword ptr [ebp+FFFFFEF0]
:00404870 50                      push eax
:00404871 E8AA7D0000              call 0040C620
:00404876 83C408                  add esp, 00000008

* Possible StringData Ref from Data Obj ->"v1.0"
                                  |
:00404879 68C8CC4200              push 0042CCC8
:0040487E 8D8DF0FEFFFF            lea ecx, dword ptr [ebp+FFFFFEF0]
:00404884 51                      push ecx
:00404885 E8967D0000              call 0040C620
:0040488A 83C408                  add esp, 00000008

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:004048D5(U)
|
:0040488D 6A00                    push 00000000       <-- Push a 0 on the stack
:0040488F E80F570000              call 00409FA3       <-- First call instruction before the CD request
:00404894 83C404                  add esp, 00000004   <-- Fix stack due to push command
:00404897 85C0                    test eax, eax       <-- Test eax for value
:00404899 753C                    jne 004048D7        <-- Conditional jump before asking for the CD!!
:0040489B 6A01                    push 00000001

* Possible StringData Ref from Data Obj ->"/LNCH073/Error"
                                  |
:0040489D 68D0CC4200              push 0042CCD0
:004048A2 E844090000              call 004051EB
:004048A7 83C404                  add esp, 00000004
:004048AA 50                      push eax

* Possible StringData Ref from Data Obj ->"/LNCH099/Please insert the CD "    <-- What got us here and why
                                        ->"into your CD-ROM player and try "  <-- we're doing this
                                        ->"again."
                                  |
:004048AB 68E0CC4200              push 0042CCE0
:004048B0 E836090000              call 004051EB
:004048B5 83C404                  add esp, 00000004
:004048B8 50                      push eax
:004048B9 6A00                    push 00000000

* Reference To: USER32.MessageBoxA, Ord:01BEh                 <-- Post a windows pop-up message box
                                  |
:004048BB FF1530344200            Call dword ptr [00423430]
:004048C1 89857CFDFFFF            mov dword ptr [ebp+FFFFFD7C], eax
:004048C7 83BD7CFDFFFF02          cmp dword ptr [ebp+FFFFFD7C], 00000002
:004048CE 7505                    jne 004048D5
:004048D0 E91E010000              jmp 004049F3                <-- Jump back up to the mystery call!!

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:004048CE(C)
|
:004048D5 EBB6                    jmp 0040488D

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:00404899(C)
|
:004048D7 E831510000              call 00409A0D                       <-- We want to get at least this far
:004048DC 8985E4FDFFFF            mov dword ptr [ebp+FFFFFDE4], eax
:004048E2 83BDE4FDFFFF04          cmp dword ptr [ebp+FFFFFDE4], 00000004
:004048E9 7F40                    jg 0040492B

* Possible StringData Ref from Data Obj ->"/LNCH075/Star Wars: Episode I "
                                        ->"Racer"
                                  |
:004048EB 6828CD4200              push 0042CD28
:004048F0 E8F6080000              call 004051EB
  -- Continuing Program Code --

	That's interesting to me, first you have a call then, the code tests eax for a zero value.  If
eax is not zero the code jumps over asking for the CD!  However, if eax is zero then up comes a windows
message box asking for the CD.  Then the code checks to see your response and will either exit to windows
or loop back up to the mystery call!  Well, let's take a closer look at that call and see what it's doing:

* Referenced by a CALL at Address:
|:0040488F                                             <-- Only called once!
|
:00409FA3 55                      push ebp
:00409FA4 8BEC                    mov ebp, esp
:00409FA6 81EC10040000            sub esp, 00000410
:00409FAC E82FFFFFFF              call 00409EE0
:00409FB1 8885FCFEFFFF            mov byte ptr [ebp+FFFFFEFC], al
:00409FB7 C685FDFEFFFF00          mov byte ptr [ebp+FFFFFEFD], 00

* Possible StringData Ref from Data Obj ->":\"         <-- Pushes a pointer to ":\" as in "D:\"
                                  |
:00409FBE 6814ED4200              push 0042ED14
:00409FC3 8D85FCFEFFFF            lea eax, dword ptr [ebp+FFFFFEFC]
:00409FC9 50                      push eax
:00409FCA E851260000              call 0040C620
:00409FCF 83C408                  add esp, 00000008
:00409FD2 8D8DF4FCFFFF            lea ecx, dword ptr [ebp+FFFFFCF4]
:00409FD8 51                      push ecx
:00409FD9 E8CCFCFFFF              call 00409CAA
:00409FDE 83C404                  add esp, 00000004
:00409FE1 8D95FCFEFFFF            lea edx, dword ptr [ebp+FFFFFEFC]
:00409FE7 52                      push edx
:00409FE8 8D85F0FBFFFF            lea eax, dword ptr [ebp+FFFFFBF0]
:00409FEE 50                      push eax
:00409FEF E81C260000              call 0040C610
:00409FF4 83C408                  add esp, 00000008
:00409FF7 8D8DF4FCFFFF            lea ecx, dword ptr [ebp+FFFFFCF4]
:00409FFD 51                      push ecx
:00409FFE 8D95F0FBFFFF            lea edx, dword ptr [ebp+FFFFFBF0]
:0040A004 52                      push edx
:0040A005 E816260000              call 0040C620
:0040A00A 83C408                  add esp, 00000008
:0040A00D 8D85F0FBFFFF            lea eax, dword ptr [ebp+FFFFFBF0]
:0040A013 50                      push eax
:0040A014 E866FBFFFF              call 00409B7F
:0040A019 83C404                  add esp, 00000004
:0040A01C 85C0                    test eax, eax
:0040A01E 745A                    je 0040A07A
:0040A020 837D0800                cmp dword ptr [ebp+08], 00000000
:0040A024 744D                    je 0040A073
:0040A026 6A00                    push 00000000
:0040A028 6A00                    push 00000000
:0040A02A 6A00                    push 00000000
:0040A02C 6A00                    push 00000000
:0040A02E 6A00                    push 00000000
:0040A030 6804010000              push 00000104
:0040A035 8D8DF8FDFFFF            lea ecx, dword ptr [ebp+FFFFFDF8]
:0040A03B 51                      push ecx
:0040A03C 8D95FCFEFFFF            lea edx, dword ptr [ebp+FFFFFEFC]
:0040A042 52                      push edx

* Reference To: KERNEL32.GetVolumeInformationA, Ord:0177h    <-- Get the volume name of the drive
                                  |
:0040A043 FF1554324200            Call dword ptr [00423254]
:0040A049 85C0                    test eax, eax
:0040A04B 7422                    je 0040A06F
:0040A04D 8B4508                  mov eax, dword ptr [ebp+08]        <-- Pointer from getvolume call
:0040A050 50                      push eax                           <-- Push it on the stack
:0040A051 8D8DF8FDFFFF            lea ecx, dword ptr [ebp+FFFFFDF8]  <-- Pointer to known volume name
:0040A057 51                      push ecx                           <-- Push it on the stack
:0040A058 E803750000              call 00411560                      <-- Compare the two
:0040A05D 83C408                  add esp, 00000008
:0040A060 85C0                    test eax, eax
:0040A062 7507                    jne 0040A06B                       <-- eax=1 means no match
:0040A064 B801000000              mov eax, 00000001                  <-- Set up for passed CD check
:0040A069 EB11                    jmp 0040A07C                       <-- Jump to exit

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:0040A062(C)
|
:0040A06B 33C0                    xor eax, eax                       <-- Failed volume comparison
:0040A06D EB0D                    jmp 0040A07C                       <-- Jump to exit

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:0040A04B(C)
|
:0040A06F 33C0                    xor eax, eax                       <-- Had an error reading volume name
:0040A071 EB09                    jmp 0040A07C                       <-- Jump to exit

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:0040A024(C)
|
:0040A073 B801000000              mov eax, 00000001                  <-- Set up for a pass
:0040A078 EB02                    jmp 0040A07C                       <-- Jump to exit

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:0040A01E(C)
|
:0040A07A 33C0                    xor eax, eax                       <-- The CD check failed

* Referenced by a (U)nconditional or (C)onditional Jump at Addresses:
|:0040A069(U), :0040A06D(U), :0040A071(U), :0040A078(U)
|
:0040A07C 8BE5                    mov esp, ebp
:0040A07E 5D                      pop ebp
:0040A07F C3                      ret                                <-- Return to the caller

	Alright, very simple here, the code get's the volume name of the drive, does a compare if
everything works out, eax is loaded with 00000001 and it returns.  If there is an error reading the
information or the volume doesn't match what it should, then eax is loaded with zero which means
the CD check failed.  Well, armed with this information we can go back up to the code at 0040488F
and change the call instruction to mov eax, 00000001 this will force the jne at 00404899 to always
be taken.  This patch allows racer.exe to function and bypasses the CD check.  One down and one to
go, on to the next half of this quest:
	To start we must now disassemble swep1rcr.exe and do the same trick as above.  This time, when
scrolling down the ref box you'll come across "swep1rcr.exe"  This is a good sign (when hunting down
CD checks) so double click it and you'll be in the middle of this routine:

* Referenced by a CALL at Addresses:
|:00423E70   , :00425456   
|
:00425500 81EC8C030000            sub esp, 0000038C
:00425506 B93B000000              mov ecx, 0000003B
:0042550B 33C0                    xor eax, eax
:0042550D 53                      push ebx
:0042550E 55                      push ebp
:0042550F 56                      push esi
:00425510 57                      push edi
:00425511 8DBC24AD010000          lea edi, dword ptr [esp+000001AD]
:00425518 F3                      repz
:00425519 AB                      stosd
:0042551A 66AB                    stosw
:0042551C AA                      stosb
:0042551D A1E4794B00              mov eax, dword ptr [004B79E4]
:00425522 85C0                    test eax, eax
:00425524 0F8467010000            je 00425691
:0042552A 8D442418                lea eax, dword ptr [esp+18]
:0042552E 50                      push eax

* Possible StringData Ref from Data Obj ->"swep1rcr.exe"      <-- What got us here
                                  |
:0042552F 680C7F4B00              push 004B7F0C

* Reference To: VERSION.GetFileVersionInfoSizeA, Ord:0001h    <-- Get info on this file
                                  |
:00425534 E8DB910700              Call 0049E714
:00425539 8BF0                    mov esi, eax
:0042553B 85F6                    test esi, esi
:0042553D 0F84AE000000            je 004255F1
:00425543 56                      push esi
:00425544 E8F79C0700              call 0049F240
:00425549 83C404                  add esp, 00000004
:0042554C 8BD8                    mov ebx, eax
:0042554E 53                      push ebx
:0042554F 56                      push esi
:00425550 6A00                    push 00000000

* Possible StringData Ref from Data Obj ->"swep1rcr.exe"
                                  |
:00425552 680C7F4B00              push 004B7F0C

* Reference To: VERSION.GetFileVersionInfoA, Ord:0000h    <-- Get more info on this file
                                  |
:00425557 E8B2910700              Call 0049E70E
:0042555C 85C0                    test eax, eax
:0042555E 0F8484000000            je 004255E8
:00425564 8D4C2414                lea ecx, dword ptr [esp+14]
:00425568 8D542410                lea edx, dword ptr [esp+10]
:0042556C 51                      push ecx
:0042556D 52                      push edx

* Possible StringData Ref from Data Obj ->"\VarFileInfo\Translation"
                                  |
:0042556E 68F07E4B00              push 004B7EF0
:00425573 53                      push ebx

* Reference To: VERSION.VerQueryValueA, Ord:000Ah
                                  |
:00425574 E88F910700              Call 0049E708
:00425579 85C0                    test eax, eax
:0042557B 746B                    je 004255E8
:0042557D 8B442410                mov eax, dword ptr [esp+10]
:00425581 33C9                    xor ecx, ecx
:00425583 33D2                    xor edx, edx
:00425585 668B4802                mov cx, word ptr [eax+02]
:00425589 668B10                  mov dx, word ptr [eax]
:0042558C 51                      push ecx
:0042558D 52                      push edx
:0042558E 8D8424A4020000          lea eax, dword ptr [esp+000002A4]

* Possible StringData Ref from Data Obj ->"\StringFileInfo\%04X%04X\FileVersion"
                                  |
:00425595 68C87E4B00              push 004B7EC8
:0042559A 50                      push eax

* Reference To: USER32.wsprintfA, Ord:0264h
                                  |
:0042559B FF15D0C14A00            Call dword ptr [004AC1D0]
:004255A1 83C410                  add esp, 00000010
:004255A4 8D4C2414                lea ecx, dword ptr [esp+14]
:004255A8 8D542410                lea edx, dword ptr [esp+10]
:004255AC 8D84249C020000          lea eax, dword ptr [esp+0000029C]
:004255B3 51                      push ecx
:004255B4 52                      push edx
:004255B5 50                      push eax
:004255B6 53                      push ebx

* Reference To: VERSION.VerQueryValueA, Ord:000Ah
                                  |
:004255B7 E84C910700              Call 0049E708
:004255BC 85C0                    test eax, eax
:004255BE 7428                    je 004255E8
:004255C0 8B7C2410                mov edi, dword ptr [esp+10]
:004255C4 83C9FF                  or ecx, FFFFFFFF
:004255C7 33C0                    xor eax, eax
:004255C9 8D94249C010000          lea edx, dword ptr [esp+0000019C]
:004255D0 F2                      repnz
:004255D1 AE                      scasb
:004255D2 F7D1                    not ecx
:004255D4 2BF9                    sub edi, ecx
:004255D6 8BC1                    mov eax, ecx
:004255D8 8BF7                    mov esi, edi
:004255DA 8BFA                    mov edi, edx
:004255DC C1E902                  shr ecx, 02
:004255DF F3                      repz
:004255E0 A5                      movsd
:004255E1 8BC8                    mov ecx, eax
:004255E3 83E103                  and ecx, 00000003
:004255E6 F3                      repz
:004255E7 A4                      movsb

* Referenced by a (U)nconditional or (C)onditional Jump at Addresses:
|:0042555E(C), :0042557B(C), :004255BE(C)
|
:004255E8 53                      push ebx
:004255E9 E8E29B0700              call 0049F1D0
:004255EE 83C404                  add esp, 00000004

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:0042553D(C)
|
:004255F1 689C554D00              push 004D559C
:004255F6 6A50                    push 00000050
:004255F8 68C0F2E900              push 00E9F2C0

* Possible StringData Ref from Data Obj ->"CD Path"        <-- Hint, hint....
                                  |
:004255FD 68C07E4B00              push 004B7EC0
:00425602 E8A97C0700              call 0049D2B0
:00425607 83C410                  add esp, 00000010
:0042560A 85C0                    test eax, eax
:0042560C 7551                    jne 0042565F
:0042560E 68C0F2E900              push 00E9F2C0

* Reference To: KERNEL32.GetDriveTypeA, Ord:00DFh            <-- Commonly used call in CD checks
                                  |
:00425613 FF15C4C04A00            Call dword ptr [004AC0C4]
:00425619 83F805                  cmp eax, 00000005          <-- 05 is the value for CD Rom drives
:0042561C 7541                    jne 0042565F               <-- If not a CD the take this jump (failed)

* Possible StringData Ref from Data Obj ->".\data\config\default\"
                                  |
:0042561E 68843E4B00              push 004B3E84
:00425623 68C0F2E900              push 00E9F2C0
:00425628 8D8C24A4000000          lea ecx, dword ptr [esp+000000A4]

* Possible StringData Ref from Data Obj ->"%s\Gnome\%swheel.map"    <-- Check for this file
                                  |
:0042562F 68A87E4B00              push 004B7EA8
:00425634 51                      push ecx
:00425635 E816950700              call 0049EB50
:0042563A 83C410                  add esp, 00000010
:0042563D 8D94249C000000          lea edx, dword ptr [esp+0000009C]

* Possible StringData Ref from Data Obj ->"w"                       <-- Write to the CD
                                  |
:00425644 68A47E4B00              push 004B7EA4
:00425649 52                      push edx
:0042564A E8619B0700              call 0049F1B0
:0042564F 83C408                  add esp, 00000008
:00425652 85C0                    test eax, eax
:00425654 745A                    je 004256B0                       <-- Take this to continue with intro
:00425656 50                      push eax
:00425657 E8649A0700              call 0049F0C0
:0042565C 83C404                  add esp, 00000004

* Referenced by a (U)nconditional or (C)onditional Jump at Addresses:
|:0042560C(C), :0042561C(C)
|
:0042565F A16CB55000              mov eax, dword ptr [0050B56C]    
:00425664 6A10                    push 00000010

* Possible StringData Ref from Data Obj ->"BAD INSTALL"
                                  |
:00425666 68987E4B00              push 004B7E98

* Possible StringData Ref from Data Obj ->"Error:  Please reinstall program "  <-- Something we don't ever
                                        ->"from CD-ROM."                       <--  want to see!
                                  |
:0042566B 68447E4B00              push 004B7E44
:00425670 50                      push eax

* Reference To: USER32.MessageBoxA, Ord:0195h
                                  |
:00425671 FF15E0C14A00            Call dword ptr [004AC1E0]

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:004257D0(C)
|
:00425677 E854EAFFFF              call 004240D0
:0042567C 6A00                    push 00000000
:0042567E E88D930700              call 0049EA10
:00425683 83C404                  add esp, 00000004
:00425686 5F                      pop edi
:00425687 5E                      pop esi
:00425688 5D                      pop ebp
:00425689 5B                      pop ebx
:0042568A 81C48C030000            add esp, 0000038C
:00425690 C3                      ret                                <-- Return to the caller

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:00425524(C)
|
:00425691 689C554D00              push 004D559C
:00425696 68C0F2E900              push 00E9F2C0
:0042569B E8B0940700              call 0049EB50
:004256A0 83C408                  add esp, 00000008
:004256A3 33C0                    xor eax, eax
:004256A5 5F                      pop edi
:004256A6 5E                      pop esi
:004256A7 5D                      pop ebp
:004256A8 5B                      pop ebx
:004256A9 81C48C030000            add esp, 0000038C
:004256AF C3                      ret                                <-- Return to the caller

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:00425654(C)                                                        <-- Got via conditional jump from above
|
* Possible StringData Ref from Data Obj ->"100_0"                    <-- Partial volume name of the CD
                                  |
:004256B0 683C7E4B00              push 004B7E3C
:004256B5 8D442420                lea eax, dword ptr [esp+20]

* Possible StringData Ref from Data Obj ->"racer%s"
                                  |
:004256B9 68347E4B00              push 004B7E34
:004256BE 50                      push eax
:004256BF E88C940700              call 0049EB50

* Reference To: KERNEL32.GetVolumeInformationA, Ord:014Fh            <-- Get the volume of the disk
                                  |
:004256C4 8B2DC8C04A00            mov ebp, dword ptr [004AC0C8]

* Reference To: USER32.MessageBoxA, Ord:0195h
                                  |
:004256CA 8B1DE0C14A00            mov ebx, dword ptr [004AC1E0]
:004256D0 83C40C                  add esp, 0000000C

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:004257D6(U)
|
:004256D3 6A00                    push 00000000
:004256D5 6A00                    push 00000000
:004256D7 6A00                    push 00000000
:004256D9 6A00                    push 00000000
:004256DB 6A00                    push 00000000
:004256DD 8D8C2430010000          lea ecx, dword ptr [esp+00000130]
:004256E4 6880000000              push 00000080
:004256E9 51                      push ecx
:004256EA 68C0F2E900              push 00E9F2C0
:004256EF FFD5                    call ebp
:004256F1 85C0                    test eax, eax
:004256F3 0F849C000000            je 00425795
:004256F9 8D7C241C                lea edi, dword ptr [esp+1C]
:004256FD 83C9FF                  or ecx, FFFFFFFF
:00425700 33C0                    xor eax, eax
:00425702 8D54241C                lea edx, dword ptr [esp+1C]
:00425706 F2                      repnz
:00425707 AE                      scasb
:00425708 F7D1                    not ecx
:0042570A 83C1FE                  add ecx, FFFFFFFE
:0042570D 8D84241C010000          lea eax, dword ptr [esp+0000011C]
:00425714 51                      push ecx
:00425715 52                      push edx
:00425716 50                      push eax
:00425717 E8B4980700              call 0049EFD0
:0042571C 83C40C                  add esp, 0000000C
:0042571F 85C0                    test eax, eax
:00425721 7578                    jne 0042579B

* Possible StringData Ref from Data Obj ->".\data\config\default\"        <-- Partial path from the CD
                                  |
:00425723 68843E4B00              push 004B3E84
:00425728 68C0F2E900              push 00E9F2C0
:0042572D 8D8C24A4000000          lea ecx, dword ptr [esp+000000A4]

* Possible StringData Ref from Data Obj ->"%s\Gnome\%swheel.map"
                                  |
:00425734 68A87E4B00              push 004B7EA8
:00425739 51                      push ecx
:0042573A E811940700              call 0049EB50
:0042573F 83C410                  add esp, 00000010
:00425742 8D94249C010000          lea edx, dword ptr [esp+0000019C]

* Possible StringData Ref from Data Obj ->"\Gnome\Data\Anims\PlanetG.znm"  <-- The animation file to play
                                  |  
:00425749 68147E4B00              push 004B7E14
:0042574E 68C0F2E900              push 00E9F2C0

* Possible StringData Ref from Data Obj ->"%s%s"
                                  |
:00425753 6824254B00              push 004B2524
:00425758 52                      push edx
:00425759 E8F2930700              call 0049EB50
:0042575E 83C410                  add esp, 00000010
:00425761 8D84249C010000          lea eax, dword ptr [esp+0000019C]
:00425768 6A00                    push 00000000
:0042576A 50                      push eax
:0042576B E8F0AD0700              call 004A0560
:00425770 8BF0                    mov esi, eax
:00425772 83C408                  add esp, 00000008
:00425775 83FEFF                  cmp esi, FFFFFFFF
:00425778 7421                    je 0042579B
:0042577A 56                      push esi
:0042577B E830AD0700              call 004A04B0
:00425780 83C404                  add esp, 00000004
:00425783 3DE7141201              cmp eax, 011214E7
:00425788 56                      push esi
:00425789 7450                    je 004257DB               <-- Need to take this jump to continue on
:0042578B E820AC0700              call 004A03B0
:00425790 83C404                  add esp, 00000004
:00425793 EB06                    jmp 0042579B

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:004256F3(C)
|
* Reference To: KERNEL32.GetLastError, Ord:00F4h
                                  |
:00425795 FF15C0C04A00            Call dword ptr [004AC0C0]

* Referenced by a (U)nconditional or (C)onditional Jump at Addresses:
|:00425721(C), :00425778(C), :00425793(U)
|
:0042579B 8D4C241C                lea ecx, dword ptr [esp+1C]
:0042579F 8D94249C020000          lea edx, dword ptr [esp+0000029C]
:004257A6 51                      push ecx

* Possible StringData Ref from Data Obj ->"Error:  Please insert CD-ROM '%s' "  <-- Not something we would
                                        ->"into drive."                         <--  ever want to see!
                                  |
:004257A7 68B07D4B00              push 004B7DB0
:004257AC 52                      push edx
:004257AD E89E930700              call 0049EB50
:004257B2 8B0D6CB55000            mov ecx, dword ptr [0050B56C]
:004257B8 83C40C                  add esp, 0000000C
:004257BB 8D84249C020000          lea eax, dword ptr [esp+0000029C]
:004257C2 6A31                    push 00000031

* Possible StringData Ref from Data Obj ->"CD ERROR"            <-- Says it all right here
                                  |
:004257C4 68A47D4B00              push 004B7DA4
:004257C9 50                      push eax
:004257CA 51                      push ecx
:004257CB FFD3                    call ebx
:004257CD 83F802                  cmp eax, 00000002
:004257D0 0F84A1FEFFFF            je 00425677
:004257D6 E9F8FEFFFF              jmp 004256D3

* Referenced by a (U)nconditional or (C)onditional Jump at Address:
|:00425789(C)
|
:004257DB E8D0AB0700              call 004A03B0

* Possible StringData Ref from Data Obj ->"\Gnome\"             <-- Partial path from the CD
                                  |
:004257E0 BF9C7D4B00              mov edi, 004B7D9C
:004257E5 83C9FF                  or ecx, FFFFFFFF
:004257E8 33C0                    xor eax, eax
:004257EA 83C404                  add esp, 00000004
:004257ED F2                      repnz
:004257EE AE                      scasb
:004257EF F7D1                    not ecx
:004257F1 2BF9                    sub edi, ecx
:004257F3 8BF7                    mov esi, edi
:004257F5 8BD1                    mov edx, ecx
:004257F7 BFC0F2E900              mov edi, 00E9F2C0
:004257FC 83C9FF                  or ecx, FFFFFFFF
:004257FF F2                      repnz
:00425800 AE                      scasb
:00425801 8BCA                    mov ecx, edx
:00425803 4F                      dec edi
:00425804 C1E902                  shr ecx, 02
:00425807 F3                      repz
:00425808 A5                      movsd
:00425809 8BCA                    mov ecx, edx
:0042580B 83E103                  and ecx, 00000003
:0042580E F3                      repz
:0042580F A4                      movsb
:00425810 5F                      pop edi
:00425811 5E                      pop esi
:00425812 5D                      pop ebp
:00425813 5B                      pop ebx
:00425814 81C48C030000            add esp, 0000038C
:0042581A C3                      ret                                <-- Return to the caller

	This routine, as long as it is, doesn't return any special value in eax so if you replace the
first instruction with a ret (C3) the CD check is effectively bypassed.  Now that the CD checks in both
exe files have been disabled or bypassed, it's time to address another problem with the game.
	The other problem with this game is:  All the music files and all of the animation files are
stored on the CD rom.  I can live without the all cut scenes, but I like the music.  So I tracked down
the routine that plays the animations and FiX'ed it so the game would skip them.  To do this you'll need
to go back to the refs box and look for a string that has something to do with the animation roiutnes
like "\Data\Anims"  If you double click on it you'll be in the middle of the routine that plays the
animation files for the game.  I will not show this routine as it's simply too long and would provide
little if any knowlegde.  However, starting with the ref, search backwards until you find the start of
the routine.  You will eventually see that this LONG routine starts at 4252A0 and is called from four
other locations.  If you trace it to the end, you'll see like the CD check this routine doesn't return
any special value either.  Replacing the first instruction with a ret code (C3) will disable all the
animations. Then if you copy the music directory to your hard drive the game will play just fine and
will no longer require you to have the CD online.  That is of course, the whole reason behind our
efforts and this tutorial.  The actual steps to crack Star Wars Episode 1 Racer are:

1.  Install the game
2.  Copy the "\Music" directory
   (from "CD":\Gnome\Data\wavs\ to your install directory in Data\wavs\)
3.  Copy the "\Anims" directory  <-- Skip if you want to kill anims anyways
   (from "CD":\Gnome\Data\ to your install directory in Data\)
4.  Make the following edits to the following files:

Edit Racer.exe
=============================================
Search for: E8 0F 57 00 00  at offset  18,575
Change to : B8 01 00 00 00

Edit swep1rcr.exe
=============================================
Search for: 81 EC 8C 03 00  at offset 149,760
Change to : C3 -- -- -- --

 - Optional: Kill the animation sequences:
Search for: 81 EC 0C 01 00  at offset 149,152
Change to : C3 -- -- -- --

For the French version: Edit Racer.exe
=============================================
Search for: E8 79 57 00 00  at offset  18,725
Change to : B8 01 00 00 00

Edit swep1rcr.exe
=============================================
Search for: 81 EC 8C 03 00  at offset 153,216
Change to : C3 -- -- -- --

 - Optional: Kill the animation sequences:
Search for: 81 EC 0C 01 00  at offset 152,608
Change to : C3 -- -- -- --


5.  Enjoy the game, graphics and races.

	You can always copy both the animation and music files to your hard drive, then you'll have a 100%
working copy of SW Episode 1 Racer on your hard drive.  The only problem is the game in this format takes up
478 megs!  This is the main reason I added the kill animation patch to the crack.  The final resault is a 268
meg install which is acceptable for this game and you'll have the music if you want it.  The music can also be
removed to free up another 76 megs, but you'll have to trace all the music routines and edit them out yourself.
That's as far as this tutorial goes, becuase this great racer has been FiX'ed!

Static Vengeance - FiX
```