tmp = [{2: '[4009b6] 400ad9: "v7 = (v8[j] + v7 + *(unsigned __int8 *)(j + a1)) % 256"'},
       {1: '[400b70] 400bc1: "v5 = (v5 + 1) % 256"'}, {2: '[400b70] 400bc1: "v5 = (v5 + 1) % 256"'},
       {2: '[400b70] 400bed: "v6 = (v6 + *(unsigned __int8 *)(v5 + a1)) % 256"'}, {
           3: '[400b70] 400c90: "*(_BYTE *)(a2 + i) ^= *(_BYTE *)((unsigned __int8)(*(_BYTE *)(v5 + a1) + *(_BYTE *)(v6 + a1)) + a1)"'}]

res = {1: [], 2: [], 3: []}
match = [0,0,0]
for i in tmp:
    # i:str
    index = str(i.keys()).split('[')[1][0]
    value = str(i.values())[14:-4]
    res[int(index)].append(value)

if len(res[1]) != 0:
    for k in res[1]:
        pattern = k[k.find('['):k.find(']')+1]
        print(pattern)
        cnt = 0
        for i in range(2, 4):
            for j in res[i]:
                if pattern in j:
                    match[i-1] = match[i-1] + 1
    if(match[1] >= 2 and match[2] >= 1):
        print(f"RC4_function at addr:0x{pattern[1:-1]}")


# print(res[1])
    # print(i)
