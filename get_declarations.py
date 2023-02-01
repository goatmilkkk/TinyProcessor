import requests
import lief
import re


def get_nt_winapis():
    """parse local ntdll to map syscall numbers to their Nt function names"""
    syscalls = {}
    ntdll = lief.parse(r"C:\Windows\SysWOW64\ntdll.dll")  # use 32-bit ntdll as x86 Nt exports are a superset of x64 Nt exports 
    for export in ntdll.exported_functions:
        if export.name.startswith("Zw"):
            syscalls["Nt" + export.name[2:]] = export.address  # replace `Zw` w/ `Nt` to be consistent w/ map_winapi_to_args()

    # sort syscalls by addr
    syscalls = [x[0] for x in sorted(syscalls.items(), key=lambda x: x[1])]
    return {k for v, k in enumerate(syscalls)}


def scrape_capemon():
    """Scrape function definitions from Capemon & map Nt function names to their arguments"""
    with open(r"references\hooks.h", "r") as f:  # https://github.com/kevoreilly/capemon/blob/capemon/hooks.h
        data = f.readlines()

        # remove single-line comments and libraries
        i = 0
        while i < len(data):
            if data[i].startswith(("/", "#")):
                data.pop(i)
            else:
                i += 1

        # remove multi-line comment at the start
        while not data[0].startswith("*"):
            data = data[1:]
        data = data[2:]
        data[0] = ";" + data[0]
        data = "".join(data).replace("\n\n\n\n", "\n\n").replace("\n\n\n", "\n\n")

        # get all function & arg names
        d = {}
        lines = data.split(";\n\nHOOKDEF")[1:]
        for line in lines:
            line = re.split(", |,\n|\n", line[1:-1])
            _, _, fx = line[:3]
            args = line[3:-1]

            # get names of Nt functions that Capemon hooks
            if fx.startswith("Nt"):

                # get argument names of Nt functions
                for i in range(len(args)):
                    args[i] = re.split(" |\t", args[i])

                    # handle optional arguments
                    if args[i][-1] == "OPTIONAL":
                        args[i] = args[i][-2]
                    else:
                        args[i] = args[i][-1]

                # handle nullary functions (i.e. fxs w/ no args)
                if "VOID" in args:
                    args.remove("VOID")
                d[fx] = args
        return d


def scrape_ntinternals():
    """Scrape function definitions in Capemon & map Nt function names to their arguments"""
    d = {}
    links = []
    base_url = "http://undocumented.ntinternals.net/"

    # get array that contains the links to Nt function names
    data = requests.get("http://undocumented.ntinternals.net/files/treearr.js").text
    start, end = data.find("["), data.find(";")
    arr = eval(data[start:end].replace("null", "'0'"))
    
    def iterate(arr):
        """recursively iterates treearr.js to get links to Nt functions"""
        for i in range(len(arr)):
            if type(arr[i]) == str:
                if arr[i].startswith("Nt"):
                    links.append(f"{base_url}{arr[i + 1]}")
            else:  # traverse list
                iterate(arr[i])
    iterate(arr)

    # parse link to get Nt function name
    for link in links:
        winapi = re.split("/|\.", link)[-2]
        response = requests.get(link).text

        # parse webpage to get Nt function arguments
        start = response.find(f"{winapi}(")
        end = start + response[start:].find(");")
        args = re.findall("""<i><font color="blue">(.*?)</font></i>""", response[start:end].replace("\r\n", ""))
        d[winapi] = args
    return d


def merge_declarations(capemon, ntinternals):
    """Fix minor errors in function declarations of different sources & merge them"""

    # fix capemon's output
    if "NtLoadDriver" in capemon:
        if capemon["NtLoadDriver"] == ['DriverServiceNAme']:
            capemon["NtLoadDriver"] = ['DriverServiceName']
            
    # fix ntinternals' output
    for winapi in ntinternals:  # remove trailing whitespace in some of the argument names
        ntinternals[winapi] = [arg.strip(" ") for arg in ntinternals[winapi]]

    # merge sources
    d = {}
    for winapi in get_nt_winapis():
        if winapi in capemon:  # prioritize capemon over ntinternals since it uses MSDN
            d[winapi] = capemon[winapi]
        elif winapi in ntinternals:
            d[winapi] = ntinternals[winapi]

    with open("declarations.out", "w") as g:
        g.write(str(d))
    print("Output written to declarations.out")


def main():
    """Scrape Nt function declarations from Capemon & Ntinternals and merge them"""
    merge_declarations(scrape_capemon(), scrape_ntinternals())


if __name__ == "__main__":
    main()
