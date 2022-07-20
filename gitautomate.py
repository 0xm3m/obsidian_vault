#!/bin/python3
"""

author: @enum-more

Automated Git commands
Automate the process of using commands such as add, commit, branch, pull, merge and blame

"""

import subprocess
import os
from pyfiglet import figlet_format
from termcolor import cprint


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
    commit = '`git status`'
    choice = input('\nDo you want to commit the changes right now to GitHub? (y/n): ').lower()
    if choice == 'y':
        run('commit', '-am',  commit)
        #os.system(commit -m `git status`)
    else:
        print('\nOkay, goodbye!\n')
    branch = input('\n[+]Push branch: ')
    choice = input('\nDo you want to push the branch right now to GitHub? (y/n): ').lower()
    if choice == 'y':
        run('push', '-u', 'origin', branch)
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


def main():
    cprint(figlet_format(logo, font='slant'), 'green')
    print(f'{info} \n')

    print('Commands to use: add, commit, branch, pull, fetch, merge, reset and blame')

    choose_command = input('Command: ').lower()

    dict = {
        'add': add,
        'commit': commit,
        'branch': branch,
        'pull': pull,
        'fetch': fetch,
        'merge': merge,
        'reset': reset,
        'blame': blame
    }

    dict.get(choose_command, lambda: "Invalid")()


if __name__ == '__main__':
    main()
