
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(undefined param_1)

{
  uint __seed;
  char *num_bytes_read;
  int cell_position;
  undefined4 exit_value;
  int in_GS_OFFSET;
  int user_turn_bool;
  int num_mosse__;
  uint AI_turn_bool;
  int match_result;
  size_t input_length;
  int user_axis_X;
  int user_axis_Y;
  int AI_axis_X;
  undefined4 AI_axis_Y;
  char buffer [128];
  int canary;
  undefined *useless_func_param;
  undefined *format_string;
  
  useless_func_param = &param_1;
  canary = *(int *)(in_GS_OFFSET + 0x14);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  format_string = (undefined *)0x0;
  setvbuf(stderr,(char *)0x0,2,0);
  __seed = time((time_t *)0x0);
  srand(__seed);
  match_result = 0;
  AI_turn_bool = 1;
  system("echo Welcome to tic-tac-toe online");
  printf(
        "Board positions are identified by the following numbers:\n1 2 3\n4 5 6\n7 8 9\nYour mark is O, mine is X."
        );
  putchar(10);
  num_mosse__ = 0;
  do {
    if (8 < num_mosse__) {
      printf("A draw.");
      putchar(10);
      exit_value = 0;
EXIT:
      if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
        exit_value = __stack_chk_fail_local();
      }
      return exit_value;
    }
    do {
      if (AI_turn_bool == 0) goto AI_TURN;
      while( true ) {
        do {
          printf("Your move: ");
          num_bytes_read = fgets(buffer,0x80,stdin);
          if (num_bytes_read == (char *)0x0) {
            exit_value = 0xffffffff;
            goto EXIT;
          }
          input_length = strlen(buffer);
        } while (input_length == 0);
        if (buffer[input_length - 1] == '\n') {
          buffer[input_length - 1] = '\0';
          input_length = input_length - 1;
        }
        format_string = &DAT_08048f0e;
        cell_position = __isoc99_sscanf(buffer,&DAT_08048f0e,&user_turn_bool);
        if (((0 < cell_position) && (0 < user_turn_bool)) && (user_turn_bool < 10)) break;
        printf("I don\'t understand: ");
        printf(buffer);
        printf(", please insert a number between 1 and 9.");
        putchar(10);
      }
      user_turn_bool = user_turn_bool + -1;
      user_axis_X = user_turn_bool / 3;
      user_axis_Y = user_turn_bool % 3;
    } while (*(int *)(b + (user_axis_X * 3 + user_axis_Y) * 4) != 0);
    *(undefined4 *)(b + (user_axis_X * 3 + user_axis_Y) * 4) = 1;
AI_TURN:
    if (AI_turn_bool == 0) {
      do {
        AI_axis_X = rand();
        AI_axis_X = AI_axis_X % 3;
        AI_axis_Y = rand();
        AI_axis_Y = AI_axis_Y % 3;
      } while (*(int *)(b + (AI_axis_X * 3 + AI_axis_Y) * 4) != 0);
      *(undefined4 *)(b + (AI_axis_X * 3 + AI_axis_Y) * 4) = 0xffffffff;
      format_string = (undefined *)(AI_axis_Y + AI_axis_X * 3 + 1);
      printf("My move: %d\n",format_string);
    }
    showboard();
    match_result = check_winner();
    if (match_result != 0) {
      if (match_result == 1) {
        printf("You win... what\'s your name?",format_string);
        num_bytes_read = fgets(buffer,0x20,stdin);
        if (num_bytes_read == (char *)0x0) {
          exit_value = 0xffffffff;
        }
        else {
          printf("Well done, ");
          puts(buffer);
          exit_value = 0;
        }
      }
      else {
        printf("I won! No flag for you.",format_string);
        putchar(10);
        exit_value = 0;
      }
      goto EXIT;
    }
    num_mosse__ = num_mosse__ + 1;
    AI_turn_bool = (uint)(AI_turn_bool == 0);
  } while( true );
}

