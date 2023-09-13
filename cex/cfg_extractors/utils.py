import hashlib
import rzpipe

def check_pie(binary):
    rz  = rzpipe.open(binary, flags=["-2"])
    res = rz.cmdj("iIj")
    if "pic" in res:
        res = res["pic"]
    else:
        res = res["PIE"]
    rz.quit()
    return res

def get_sha256_file(filename):
    with open(filename,'rb') as f_binary:
        res = hashlib.sha256(f_binary.read()).hexdigest()
    return res
