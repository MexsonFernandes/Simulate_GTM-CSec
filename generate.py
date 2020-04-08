import numpy
import pandas as pd
import time
import schedule
import matplotlib.pyplot as plt
from drawnow import drawnow
import random

global count, x_axis, defender, attacker, seconds, generated_values

mue = list(numpy.arange(0.5, 1.00, 0.01)) # values from 0 -> 0.99
alpha = mue # values from 0 -> 0.99
gamma = mue # values from 0 -> 0.99

Bds = list([-5, 0, 5])
Gat = Bds

Eds = list(numpy.arange(0, 1.00, 0.01))
Hhp = Eds
Rat = Hhp
Vass = list(numpy.arange(1, 5, 1))

df = pd.DataFrame(columns=[
    'signature', # u
    'anomaly', # a 
    'honeypot', # y
    'gain_detection', # B
    'gain_attack', # G
    'ids_energy', # E
    'ids_honeypot', # H
    'resource', # R
    'asset_value' # V
])

generated_values = {
    'a': 0,
    'u': 0,
    'y': 0,
    'B': 0,
    'G': 0,
    'R': 0,
    'V': 0,
    'E': 0,
    'H': 0
}
def check_constraint(time, a, u, y, B, G, R, V, E, H):
    global generated_values
    if generated_values['E'] < E or generated_values['H'] < H or generated_values['R'] < R:
        return True
    else: 
        return False

seconds = int(input("Enter number of seconds: "))

def generate():
    global count, defender, attacker, x_axis, generated_values

    # check time
    if count == seconds + 1:
        raise

    a, u, y, B, G, R, V, E, H = get_random_value(count)

    Ud = case_3_get_pay_off_defender(a, u, y, B, G, R, V, E, H)
    Ua = case_3_get_pay_off_attacker(a, u, y, B, G, R, V, E, H)

    if check_constraint(count, a, u, y, B, G, R, V, E, H):
        # update x axis
        x_axis.append(count)
        
        # update graph
        defender.append(Ud)
        attacker.append(Ua)
        drawnow(create_plot)
        generated_values = {
            'a': a,
            'u': u,
            'y': y,
            'B': B,
            'G': G,
            'R': R,
            'V': V,
            'E': E,
            'H': H
        }
    count += 1

schedule.every(1).second.do(generate)

x_axis = []
defender = []
attacker = []

def create_plot():
    plt.xlabel('Time (sec)')
    plt.ylabel('Pay Off')
    plt.plot(x_axis, defender, label='defender')
    plt.plot(x_axis, attacker, label='attacker')
    plt.legend()
    plt.pause(1e-3)
    plt.savefig('output.png')

count = 0

def case_2_get_pay_off_defender(a, u, y, B, G, R, V, E, H):
    p = u/(u+a-y)
    q = (u-y-2*a)/(u-y-a)-(V)/((u-y-a)*(B+V))-(H)/((u-y-a)*(B+V))
    return (p*q*u*B) + (p*q*u*V) + (p*V) + (q*y*B) + (q*y*V) - (p*q*y*B) - (p*q*y*V) - (p*a*B) - (p*a*V) + (p*H) - (q*a*B) - (q*a*V) + (p*q*a*B) + (p*q*a*V)

def case_2_get_pay_off_attacker(a, u, y, B, G, R, V, E, H):
    p = u/(u+a-y)
    q = (u-y-2*a)/(u-y-a)-(V)/((u-y-a)*(B+V))-(H)/((u-y-a)*(B+V))
    return  (4*G) - (p*u*G) + (p*a*G) - (2*p*G) - (q*y*G) + (q*a*G) - (p*q*u*G) + (p*q*y*G) - (p*q*a*G) - (a*G) - (2*R) 

def case_3_get_pay_off_defender(a, u, y, B, G, R, V, E, H):
    p=a/(a+u+y)
    q=(u+y)/(u+a+y) + V/((u+a+y)*(B+V)) + H/((u+y+a)*(B+V))
    return (p*a*B) - (p*V) + (p*a*V) - (p*q*a*B) - (p*q*a*V) + (p*u*B) - (2*q*V) - (q*y*B) + (q*y*V) - (q*H) - (p*q*u*B) - (p*q*u*V) - (p*q*y*B) - (p*q*y*V) + (p*H) + (q*E) + (2*q*V) + (q*H)

def case_3_get_pay_off_attacker(a, u, y, B, G, R, V, E, H):
    p=a/(a+u+y)
    q=(u+y)/(u+a+y) + V/((u+a+y)*(B+V)) + H/((u+y+a)*(B+V))
    return (p*G) - (p*a*G) - (p*R) + (p*q*a*G) - (u*q*G) - (q*a*G) + (p*q*u*G) + (p*q*y*G) + (2*G) - (2*R) - (2*p*G) + (2*p*R) 

def case_4_get_pay_off_defender(a, u, y, B, G, R, V, E, H):
    p = y/(y+a-u)
    q=(y-u-2*a)/(y-u-a) + V/((y-u-a)*(B+V)) + H/((y-u-a)*(B+V)) - (2*E)/((y-u-a)*(B+V))
    return (p*q*y*B) + (p*q*y*V) - (p*H) - (p*V) - (p*q*u*B) - (p*q*u*V) - (p*a*B) + (2*p*V) - (p*a*V) + (2*p*E) + (p*q*a*B) + (p*q*a*V)

def case_4_get_pay_off_attacker(a, u, y, B, G, R, V, E, H):
    p = y/(y+a-u)
    q=(y-u-2*a)/(y-u-a) + V/((y-u-a)*(B+V)) + H/((y-u-a)*(B+V)) - (2*E)/((y-u-a)*(B+V))
    return ((-p*q*y*G) + (p*G) - (p*R) - (y*u*G) + (p*q*u*G) + (2*G) - (2*R) - (a*G) - (2*p*G) + (2*p*R) + (p*a*G) + (y*a*G) - (p*q*a*G))

def case_5_get_pay_off_defender(a, u, y, B, G, R, V, E, H):
    p = a/(u+a)
    q = p
    return ((p*q*u*B) + (p*q*a*B) + (p*q*u*V) + (p*q*a*V) - (p*a*B) - (p*a*V) - (q*a*B) - (q*a*V))

def case_5_get_pay_off_attacker(a, u, y, B, G, R, V, E, H):
    p = a/(u+a)
    q = p
    return ((-p*q*u*G) + 1 - (a*G) - R + (p*a*G) + (q*a*G) - (p*q*a*G))\

def case_6_get_pay_off_defender(a, u, y, B, G, R, V, E, H):
    p = y/(y-u)
    q = (E-H)/(u-y)
    return (p*q*u*B) + (p*q*u*V) + (q*y*B) + (q*y*V) - (p*q*y*B) - (p*q*y*V) - (H) - (V) + (p*H) - (p*E)

def case_6_get_pay_off_attacker(a, u, y, B, G, R, V, E, H):
    p = y/(y-u)
    q = (E-H)/(u-y)
    return (-p*q*u*G) - (q*y*G) - (p*q*G) + (p*q*a*G) + (p*q*R) + (G) - (R) + (p*q*G) - (p*q*R)

def case_7_get_pay_off_defender(a, u, y, B, G, R, V, E, H):
    p=y/(y+a)
    q=a/(a+y)
    return (q*y*B) + (q*y*V) - (p*q*y*B) - (p*q*a*V) + (p*a*B) + (p*a*V) - (p*q*a*B) - (p*q*a*V) - (H) - (V)

def case_7_get_pay_off_attacker(a, u, y, B, G, R, V, E, H):
    p=y/(y+a)
    q=a/(a+y)
    return (p*a*G) + (p*q*a*G) - (p*y*G) + (p*q*y*G) + (G) - (R)

def get_random_value(time):
    a = random.choice(alpha)
    y = random.choice(gamma)
    u = random.choice(mue)
    B = random.choice(Bds)
    G = random.choice(Gat)
    R = random.choice(Rat)
    V = random.choice(Vass)
    H = random.choice(Hhp)
    E = random.choice(Eds)
    return a, u, y, B, G, R, V, E, H

while True:
    schedule.run_pending()
    time.sleep(1)