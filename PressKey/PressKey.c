#include <conio.h>
#include <windows.h>
#include <stdio.h>

#define LEFT_ARROW_key 0x25
#define UP_ARROW_key 0x26
#define RIGHT_ARROW_key 0x27
#define DOWN_ARROW_key 0x28

#define PRESS -0x7fff

#define Q_KEY 0x51
#define Z_KEY 0x5a
#define D_KEY 0x44
#define S_KEY 0x53

/*
cf : <https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes>
*/

void pressKey(int KEY, INPUT keyboard);

int main(void)
{
	/* START */
	printf("Running RaccoonKeyCyberPunk\nLEFT_ARROW => Q\nUP_ARROW => Z\nRIGHT_ARROW = > D\nDOWN_ARROW => S\n");

	/* define keyboard var */
	INPUT keyboard;

	/* define the struct */
	keyboard.type = INPUT_KEYBOARD;
	keyboard.ki.wScan = 0;
	keyboard.ki.time = 0;
	keyboard.ki.dwExtraInfo = 0;

	/* infinite loops */
	while (1)
	{
		/* Sleep to not take all ressources */
		Sleep(20);

		/* Check which Key is press */
		/* Left Arrow */
		if (GetAsyncKeyState(LEFT_ARROW_key) == PRESS) pressKey(LEFT_ARROW_key, keyboard);
		/* Up Arrow */
		if (GetAsyncKeyState(UP_ARROW_key) == PRESS) pressKey(UP_ARROW_key, keyboard);
		/* Right Arrow */
		if (GetAsyncKeyState(RIGHT_ARROW_key) == PRESS) pressKey(RIGHT_ARROW_key, keyboard);
		/* Down Arrow */
		if (GetAsyncKeyState(DOWN_ARROW_key) == PRESS) pressKey(DOWN_ARROW_key, keyboard);
	}
	return 0;
}

void pressKey(int KEY, INPUT keyboard)
{
	/* Q Key */
	if (KEY == LEFT_ARROW_key) keyboard.ki.wVk = Q_KEY;
	/* Z Key */
	else if (KEY == UP_ARROW_key) keyboard.ki.wVk = Z_KEY;
	/* D Key */
	else if (KEY == RIGHT_ARROW_key) keyboard.ki.wVk = D_KEY;
	/* S Key */
	else if (KEY == DOWN_ARROW_key) keyboard.ki.wVk = S_KEY;

	/* Press Key */
	keyboard.ki.dwFlags = 0x0;
	SendInput(1, &keyboard, sizeof(INPUT));
	/* Release Key */
	keyboard.ki.dwFlags = 0x2;
	SendInput(1, &keyboard, sizeof(INPUT));
}