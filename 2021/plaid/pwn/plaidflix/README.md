# Plaid CTF 2021 - Pwn - PlaidFlix (250pts)
The challenge zip contains:

- challenge/Dockerfile
- challenge/bin/flag.txt
- challenge/bin/plaidflix

## 0. Environment
The included Dockerfile sets up the `plaidflix` application to run on an ubuntu:20.10 image.

To figure out the libc version I built the image and executed libc
```bash
[lucas: challenge] docker exec -it stupefied_carver ldd plaidflix
        linux-vdso.so.1 (0x00007fff211be000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7e0bca3000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f7e0be98000)
[lucas: challenge] docker exec -it stupefied_carver /lib/x86_64-linux-gnu/libc.so.6 
GNU C Library (Ubuntu GLIBC 2.32-0ubuntu3) release release version 2.32.
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 10.2.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

Next I checked the binary permissions:
```bash
[lucas: bin] checksec ./plaidflix
[*] '/home/lucas/ctfs/plaid/pwn/flix/raw/challenge/bin/plaidflix'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We are looking at a target with a modern libc and full protections.

## 1. Reverse Engineering

Running the application presents us with a menu with multiple submenus

- Main menu:
```text
[lucas: bin] ./plaidflix 
__________.__         .__    .___ _____.__  .__        
\______   \  | _____  |__| __| _// ____\  | |__|__  ___
 |     ___/  | \__  \ |  |/ __ |\   __\|  | |  \  \/  /
 |    |   |  |__/ __ \|  / /_/ | |  |  |  |_|  |>    < 
 |____|   |____(____  /__\____ | |__|  |____/__/__/\_ \
                    \/        \/                     \/


What is your name?
> %x
Hello %x!

What do you want to do?
=======================
0 - Manage movies
1 - Manage friends
2 - Delete Account
3 - Exit
=======================
```

- Movie Menu
```text
This is the place to manage your movies.
Plaidflix recommendation: Swordfish!
==============================
0 - Add movie
1 - Remove movie
2 - Show movies
3 - Share movie with a friend
==============================
```
- Friend Menu
```text
This is the place to manage your real and imaginary friends.
=======================
0 - Add friend
1 - Remove friend
2 - Show friends
=======================
```

- Delete Account Sub menu
```text
Are you sure you want to delete you account? (y/N)
> y

We're sorry that you want to delete your account.
Please leave us some feedback!
=======================
0 - Add feedback
1 - Delete feedback
2 - Add contact details
3 - Submit feedback
=======================
> 
```

The format of this application immediately hints at a heap exploitation challenge as it gives users
the ability to create and delete multiple data types.

I loaded the binary into ghidra and used the context from the menus to label various functions (i.e. `add_movie`, `add_friend`, `delete_friend`, and so on)

Since it was obvious it was a heap challenge I checked all the references to malloc:
```
 malloc	XREF[6]:	add_movie:00101415(c), 
			add_movie:00101456(c), 
			add_friend:00101a9c(c), 
			add_friend:00101adc(c), 
			add_feedback:00101d5b(c), 
			add_contact_info:00101ec7(c)  
```

- `add_movie` 
After some other checks `add_movie` called `malloc(0x20)` and stored the returned pointer in a global
```c
pvVar3 = malloc(0x20);
*(void **)(&DAT_001060c0 + (long)local_28 * 8) = pvVar3;
```

Next it prompts the user for title and rating information and stores in at offsets into this malloc'ed region.
It also `malloc(0x20)` bytes for the title. 
```c
lVar1 = *(long *)(&DAT_001060c0 + (long)local_28 * 8);
pvVar3 = malloc((long)local_24);
*(void **)(lVar1 + 8) = pvVar3;
puts("\nWhat movie title do you want to add?");
printf("> ");
get_input(*(undefined8 *)(*(long *)(&DAT_001060c0 + (long)local_28 * 8) + 8),(long)local_24, (long)local_24);
```

After reversing the rest of the function it was apparent the first malloc was for a struct:
```c
struct movie {
    ulong rating;
    char * title; /* malloc(0x20) */
    ulong shared; /* init = 0 */
    char * friend_name; /* init = 0 */
};
```

The created movie is stored at `DAT_001060c0` which I renamed to `movie_list`. After creating the struct and renaming
a few more variable the `add_movie` is pretty readable:
```c 
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  0x20 = 0x20;
  i = 0;
  do {
    if (6 < i) {
LAB_0010158b:
      if (6 < i) {
        puts("That\'s too many movies!\n");
      }
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    if (movie_list[i] == (movie *)0x0) {
      new_movie = (movie *)malloc(0x20);
      movie_list[i] = new_movie;
      new_movie_ = movie_list[i];
      pcVar2 = (char *)malloc((long)0x20);
      new_movie_->title = pcVar2;
      puts("\nWhat movie title do you want to add?");
      printf("> ");
      get_input(movie_list[i]->title,(long)0x20,(long)0x20);
      puts("\nHow good is this movie (1-5 stars)?");
      printf("> ");
      iVar1 = __isoc99_fscanf(stdin,&%hhd,&local_2a);
      if (iVar1 != 1) {
        FUN_00101289("could not read rating!");
      }
      iVar1 = getchar();
      local_29 = (undefined)iVar1;
      if ((5 < local_2a) || (local_2a == 0)) {
        FUN_00101289("Invalid rating!");
      }
      movie_list[i]->rating = (ulong)local_2a;
      *(undefined4 *)&movie_list[i]->shared = 0;
      movie_list[i]->friend_name = (char *)0x0;
      goto LAB_0010158b;
    }
    i = i + 1;
  } while( true );
}
```

I continued reversing the rest of the functions. Here are the summaries

- `add_friend` has two malloc one of size 8 and one of user controlled size between 0x30 and 0x90 bytes. The first is stored in another global list at `DAT_00106080` and points to the second. The second contains the user provided name of the friend. 
```c
char ** friend_list[8];
// alternatively
struct friend {
	char * name;
};

struct * friend[8];
```

- `add_feedback` stores char * in another global list of size 10. The mallocs are 0x100 bytes. It also sets a bool in another
array to 1 and will only add feedback if its index in the second array is 0.

- `add_contact_info` checks if a global bool is 0 and if so malloc(0x120) bytes to store user provided contact information. Then it sets the bool to 1. This means you can only create contact info once.

## 2. Vulnerabilities.
The `share_movie` function placed the name ptr of a `friend struct` in to the friend\_name field of the `movie struct`.
If the same friend was deleted, its memory was freed but the pointer in the `movie struct` was not removed. After the free
this pointer would still point to the heap.
