- [x] Push constants to the `ClassFile` struct

- [x] Push methods but only with `Code` attribute because i don't give a shit about everithing else

- [x] Try to construct simple class file without even code, serialize that shit and check using `javap`

- [x] Serialize class with some code

- [x] Construct runnable class, that prints `Hello, world` and try to run it

- [x] Figure out whether code attributes is mandatory
      For version >50 attribute `StackMapTable` is required, but i think we can easy implement it

- [x] Code refactoring, naming conventions etc.

- [x] Implement `StackMapTable` attribute generation
      How i understand, you can just append the frame with all variables
      at the beginning of a function and then on every branching instruction
      push `same_frame`. I've even check this in Java.
      So, if it will work, I will be glad :)
      
      - [ ] We need to generate local variable initialization and only then create new `full_frame`.
            In other way it will not work (sadge). But maybe initialization is not that difficult.
            An example for integers:
            ```
            bipush 0
            istore_0
            bipush 0
            istore_1
            ```

- [x] Implement super basic assembler and publish the project on GitHub

- [ ] `jasm:` Implement branching instructions

- [ ] `jasm:` Implement `ldc*` instructions (load constants)

- [ ] `jasm:` Update format for instruction operands (e.g "MyClass.field:I" -> MyClass field I)

- [ ] Try to find some simple frontend for the language because i don't want implement it myself.
      I am building only a backend, building a frontend is also a difficult problem.


- [ ] Implement `max_stack` and `max_locals` calculating



`TODO:` Think about implementing stack-based language something like tsoding's `porth`.
Anyway we will implement backand for language first. So we can try to implement different type of
languages
