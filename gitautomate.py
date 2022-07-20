#!/bin/python3
"""

author: @enum-more

Automated Git commands
Automate the process of using commands such as add, commit, branch, pull, merge and blame

"""

import subprocess
import os
import git
from pyfiglet import figlet_format
from termcolor import cprint
from git import Repo


logo = 'Git-Commands'


class color:
    NOTICE = '\033[91m'
    END = '\033[0m'


info = color.NOTICE + '''
Automate the process of using commands such as add, commit, branch, pull, merge and blame.\n''' + color.END


dict = {}

def run(*args):
    return subprocess.check_call(['git'] + list(args))

def add():
    run('add', '.')


def commit():
    commit =  input('\n[+]Commit message: ')
    choice = input('\nDo you want to commit the changes right now to GitHub? (y/n): ').lower()
    if choice == 'y':
        run('commit', '-am',  commit)
    else:
        print('\nOkay, goodbye!\n')
    branch = input('\n[+]Push branch: ')
    choice = input('\nDo you want to push the branch right now to GitHub? (y/n): ').lower()
    while True:
        if choice == 'y':
            run('push', '-u', 'origin', branch)
            break
        else:
            print('\nOkay, goodbye!\n')



def branch():
    branch = input('\n[+]Checkout branch: ')
    run('checkout', '-b', branch)

    choice = input('\nDo you want to push the branch right now to GitHub? (y/n): ').lower()

    if choice == 'y':
        run('push', '-u', 'origin', branch)
    else:
        print('\nOkay, goodbye!\n')


def pull():
    #print('\n[+]Pull the changes.')
    branch = input('\n[+]Pull the branch changes: ')
    choice = input('\nDo you want to pull the changes from GitHub? (y/n): ').lower()

    if choice == 'y':
        run('pull', 'origin', branch)
    else:
        print('\nOkay, goodbye!\n')


def fetch():
    print('\nFetches changes from the current folder.')
    run('fetch')


def merge():
    branch = input('\n[+]Merge branch: ')
    run('merge', branch)


def reset():
    filename = input('\n[+]Reset file: ')
    run('reset', filename)


def blame():
    file = input('\n[+]Blame file: ')
    run('blame', file)


def exit():
    print(quit)
    quit()

def main():
    cprint(figlet_format(logo, font='slant'), 'green')
    print(f'{info} \n')


    print('[1] Add')
    print('[2] Commit')
    print('[3] Branch')
    print('[4] Pull')
    print('[5] Fetch')
    print('[6] Merge')
    print('[7] Reset')
    print('[8] Blame')
    print('[9] Exit')
    

    choose_command = int(input('Command: '))
    while choose_command > 0:
        if choose_command == 1:
            add()
            continue

        elif choose_command == 2:
            commit()

        elif choose_command == 3:
            branch()
            break

        elif choose_command == 4:
            pull()
            break

        elif choose_command == 5:
            fetch() 
            break   

        elif choose_command == 6:
            merge()
            break
            
        elif choose_command == 7:
            reset() 
            break 
            
        elif choose_command == 8:
            blame() 
            break  

        elif choose_command == 9:
            exit()
            break

        else:
            print('Invalid choice')    
            continue


        dict = {
                'add': 1,
                'commit': 2,
                'branch': 3,
                'pull': 4,
                'fetch': 5,
                'merge': 6,
                'reset': 7,
                'blame': 8,
                'exit': 9
        }

        dict.get(choose_command, lambda: "Invalid")()


if __name__ == '__main__':
    main()
