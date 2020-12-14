from Check import readinput

def numbers_to_strings(argument): 
    switcher = { 
        0: "zero", 
        1: "one", 
        2: "two",
        3: "three" 
    } 
    return switcher.get(argument, "nothing") 
  
# Driver program 
if __name__ == "__main__": 
    argument=0
    print (numbers_to_strings(argument)) 