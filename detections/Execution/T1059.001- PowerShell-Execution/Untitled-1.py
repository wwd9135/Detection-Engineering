with open ("Untitled-2.txt", 'r') as f:
    data = f.read()
lister = []
for i in data.splitlines():
    lister.append(i)
List2 = []
for i in lister:
    i = i.replace('ScriptBlockText contains ', '')
    i = i.replace('or', '')
    List2.append(i)
for i in List2:
    print(f"{i},")