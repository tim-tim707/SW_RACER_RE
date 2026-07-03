#!/usr/bin/env python3
"""Extract localized strings from the Aspyr Switch NSO (`main`) and key-align them to the
PC key master (assets/lang/en/racer.tab).

`main` is an LZ4-compressed 32-bit-ARM NSO0. Decompress the 3 segments into a flat VA image
(VA == image offset). UI/dialogue strings live in .rodata; a .data pointer table holds 5-slot
tuples, column order [EN, FR, DE, ES, JA] (stride 0x14). We locate contiguous pointer runs,
pick each run's EN column by the phase that maximizes exact matches to the master's English
values (self-validating), then read FR/DE/ES/JA per tuple and key by the English string.

Findings baked in: German (slot 3) is almost entirely English-fallback in this build. Chinese
(ZH-Hans) is present in rodata but has NO static pointers (runtime-computed) -> not extractable
here; needs an xref/code pass in main.i64/IDA.
"""
import struct, io, sys, os

NSO   = sys.argv[1] if len(sys.argv)>1 else r"C:/Users/louri/Downloads/xciDecrypted/xciDecrypted/main"
MASTER= "assets/lang/en/racer.tab"
OUTDIR= "assets/lang/_switch_extract"
RO_LO, RO_HI = 0xe8000, 0x113f80
LANGS = ["fr","de","es","ja"]   # slots 1..4 relative to the EN column

def lz4_decompress(src):
    out=bytearray(); i=0; n=len(src)
    while i<n:
        tok=src[i]; i+=1; lit=tok>>4
        if lit==15:
            while True:
                b=src[i]; i+=1; lit+=b
                if b!=255: break
        out+=src[i:i+lit]; i+=lit
        if i>=n: break
        off=src[i]|(src[i+1]<<8); i+=2
        ml=tok&0xf
        if ml==15:
            while True:
                b=src[i]; i+=1; ml+=b
                if b!=255: break
        ml+=4; st=len(out)-off
        for k in range(ml): out.append(out[st+k])
    return bytes(out)

def build_image(path):
    d=open(path,'rb').read(); segs=[]; top=0
    for ho,co in [(0x10,0x60),(0x20,0x64),(0x30,0x68)]:
        fo,mo,ds=struct.unpack_from('<III',d,ho); cs=struct.unpack_from('<I',d,co)[0]
        dec=lz4_decompress(d[fo:fo+cs]); segs.append((mo,dec)); top=max(top,mo+len(dec))
    img=bytearray(top)
    for mo,dec in segs: img[mo:mo+len(dec)]=dec
    return bytes(img)

def main():
    img=build_image(NSO)
    def s_at(v):
        if not(RO_LO<=v<RO_HI): return None
        j=img.find(b'\x00',v,RO_HI)
        try: return img[v:j].decode('utf-8')
        except: return None
    master=[]
    for line in io.open(MASTER,encoding='cp1252'):
        line=line.rstrip('\r\n')
        if '\t' in line:
            k,v=line.split('\t',1); master.append((k,v))
    en2key={v:k for k,v in master}; en_set=set(en2key)
    # contiguous runs of 4-aligned words that are rodata string pointers
    def is_ro(v): return RO_LO<=v<RO_HI
    runs=[]; p=0x114000; N=len(img)
    while p<N-3:
        if is_ro(struct.unpack_from('<I',img,p)[0]):
            q=p
            while q<N-3 and is_ro(struct.unpack_from('<I',img,q)[0]): q+=4
            if (q-p)//4>=10: runs.append((p,q))
            p=q
        else: p+=4
    cols={l:{} for l in LANGS}; ntuples=0
    for a,b in runs:
        words=[struct.unpack_from('<I',img,x)[0] for x in range(a,b,4)]
        # pick phase (0..4) that maximizes col0 exact-matches to master EN
        best=(-1,0)
        for ph in range(5):
            hits=sum(1 for i in range(ph,len(words)-4,5) if (s_at(words[i]) in en_set))
            if hits>best[0]: best=(hits,ph)
        hits,ph=best
        if hits<3: continue   # not the EN-keyed 5-lang table
        for i in range(ph,len(words)-4,5):
            en=s_at(words[i]); key=en2key.get(en)
            if key is None: continue
            ntuples+=1
            for idx,l in enumerate(LANGS,start=1):
                t=s_at(words[i+idx])
                if t is not None and t!=en:
                    cols[l][key]=t
    os.makedirs(OUTDIR,exist_ok=True)
    for l in LANGS:
        with io.open(f"{OUTDIR}/{l}.racer.tab",'w',encoding='utf-8',newline='\r\n') as f:
            for k,_ in master:
                if k in cols[l]: f.write(f"{k}\t{cols[l][k]}\n")
        print(f"{l}: {len(cols[l])} translated keys")
    print(f"keyed tuples: {ntuples}")

main()
