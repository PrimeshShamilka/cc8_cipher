import random
import timeit

def randomString(stringLength=16):
    return '{0:016b}'.format(random.randint(0,65536))

start = timeit.default_timer()
count = 1000000 #change count. default = 1,000,000
st = ""
for i in range(count):
    print(i)
    st+=randomString()+" "+randomString()+"\n"
stop = timeit.default_timer()
print("Done")
print('Time: ', stop - start)

with open("key-values.txt","w+") as file:
    file.write(st)
    file.close()
