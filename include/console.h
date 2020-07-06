#include <stdio.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <termios.h>

struct winsize current_terminal;

struct winsize * terminal_init()
{
	/* get the size of terminal */
	ioctl(STDIN_FILENO, TIOCGWINSZ, &current_terminal);
}

