#include <time.h>
#include <stdio.h>

void
print_current_system_time(void) {
    time_t seconds;
    struct tm *cur_time = NULL;

    seconds = time(NULL); //This will store the time in seconds
    cur_time = localtime(&seconds); //Get current time using localtime()

    printf("%02d:%02d:%02d\n",
                cur_time->tm_hour,
                cur_time->tm_min,
                cur_time->tm_sec);
}