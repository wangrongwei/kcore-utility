#ifndef __CONSOLE_H__
#define __CONSOLE_H__

#include <stdio.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <termios.h>

struct winsize current_terminal;

struct winsize * terminal_init()
{
	/* get the size of terminal */
#if 0
	ioctl(STDIN_FILENO, TIOCGWINSZ, &current_terminal);
#endif
}
#endif
