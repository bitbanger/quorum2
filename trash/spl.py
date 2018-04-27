import sys

with open('repls', 'r') as f:
    lines = f.readlines()
    idx = 0
    for i in range(0, len(lines), 2):
        # print lines[i].strip()
        if idx == int(sys.argv[1]):
            print lines[i+1].strip()
            quit()
        idx += 1
