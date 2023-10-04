
<i class="fas fa-file-alt"></i> Contents</h4></header>
              <ul class="toc__menu"><li>
<a href="#steganography---a-list-of-useful-tools-and-resources">Steganography - A list of useful tools and resources</a><ul>
<li><a href="#steganography">Steganography</a></li>
<li><a href="https://futureboy.us/stegano/decinput.html">Steganographic Decoder</a></li>
<li><a href="#tools">Tools</a></li>
<li><a href="#steghide">Steghide</a></li>
<li><a href="#foremost">Foremost</a></li>
<li><a href="#stegsolve">Stegsolve</a></li>
<li><a href="#strings">Strings</a></li>
<li><a href="#exiftool">Exiftool</a></li>
<li><a href="#exiv2">Exiv2</a></li>
<li><a href="#binwalk">Binwalk</a></li>
<li><a href="#zsteg">Zsteg</a></li>
<li><a href="#wavsteg">Wavsteg</a></li>
<li><a href="#sonic-visualizer">Sonic visualizer</a></li>
<li><a href="#web-tools">Web Tools</a></li>
<li><a href="#unicode-text-steganography">Unicode Text Steganography</a></li>
<li><a href="#npiet-online">npiet online</a></li>
<li><a href="#dcodefr">dcode.fr</a></li>
<li><a href="#bruteforcers">Bruteforcers</a></li>
<li><a href="#stegcracker">StegCracker</a></li>
<li><a href="#fcrackzip">Fcrackzip</a></li>
<li><a href="#challenges">Challenges</a></li>
</ul>
</li></ul>

            </nav>
          </aside>
        
        <h1 id="steganography---a-list-of-useful-tools-and-resources">Steganography - A list of useful tools and resources</h1>

<h2 id="steganography">Steganography</h2>
<p>Steganography is hiding a file or a message inside of another file , there are many fun steganography CTF challenges out there where the flag is hidden in an image , audio file or even other types of files. Here is a list of the most tools I use and some other useful resources.<br>
Note : This list will be updated regularly , feel free to pm if you have any suggestions 
Last update : 29.1.2019
<br><img src="/images/lists/stego/0.png" alt="" class="align-center"><br><br></p>

<h2 id="tools">Tools</h2>

<h2 id="steghide">Steghide</h2>
<p>Steghide is a steganography program that hides data in various kinds of image and audio files , only supports these file formats : <code class="language-plaintext highlighter-rouge">JPEG, BMP, WAV and AU</code>. but it’s also useful for extracting embedded and encrypted data from other files.<br>
It can be installed with <code class="language-plaintext highlighter-rouge">apt</code> however the <a href="https://github.com/StefanoDeVuono/steghide" target="_blank" rel="noopener noreferrer">source</a> can be found on github.<br></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">steghide info file</code> : displays info about a file whether it has embedded data or not.<br>
<code class="language-plaintext highlighter-rouge">steghide extract -sf file</code> : extracts embedded data from a file</p>

<h2 id="foremost">Foremost</h2>
<p>Foremost is a program that recovers files based on their headers , footers and internal data structures , I find it useful when dealing with png images.<br>
It can be installed with <code class="language-plaintext highlighter-rouge">apt</code> however the <a href="https://github.com/korczis/foremost" target="_blank" rel="noopener noreferrer">source</a> can be found on github.<br></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">foremost -i file</code> : extracts data from the given file.<br></p>

<h2 id="stegsolve">Stegsolve</h2>
<p>Sometimes there is a message or a text hidden in the image itself and in order to view it you need to apply some color filters or play with the color levels. You can do it with GIMP or Photoshop or any other image editing software but stegsolve made it easier. it’s a small java tool that applies many color filters on images. Personally i find it very useful.
<br>You can get it from <a href="https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve" target="_blank" rel="noopener noreferrer">github</a></p>

<h2 id="strings">Strings</h2>
<p>Strings is a linux tool that displays printable strings in a file. That simple tool can be very helpful when solving stego challenges. Usually the embedded data is password protected or encrypted and sometimes the password is actaully in the file itself and can be easily viewed by using strings.
It’s a default linux tool so you don’t need to install anything.<br></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">strings file</code> : displays printable strings in the given file.<br></p>

<h2 id="exiftool">Exiftool</h2>
<p>Sometimes important stuff is hidden in the metadata of the image or the file , exiftool can be very helpful to view the metadata of the files.<br>
You can get it from <a href="https://www.sno.phy.queensu.ca/~phil/exiftool/" target="_blank" rel="noopener noreferrer">here</a></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">exiftool file</code> : shows the metadata of the given file</p>

<h2 id="exiv2">Exiv2</h2>
<p>A tool similar to exiftool.<br>
It can be installed with <code class="language-plaintext highlighter-rouge">apt</code> however the <a href="https://github.com/Exiv2/exiv2" target="_blank" rel="noopener noreferrer">source</a> can be found on github.<br>
<a href="http://www.exiv2.org/" target="_blank" rel="noopener noreferrer">Official website</a></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">exiv2 file</code> : shows the metadata of the given file</p>

<h2 id="binwalk">Binwalk</h2>
<p>Binwalk is a tool for searching binary files like images and audio files for embedded files and data.<br>
It can be installed with <code class="language-plaintext highlighter-rouge">apt</code> however the <a href="https://github.com/ReFirmLabs/binwalk" target="_blank" rel="noopener noreferrer">source</a> can be found on github.<br></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">binwalk file</code> : Displays the embedded data in the given file
<br><code class="language-plaintext highlighter-rouge">binwalk -e file</code> : Displays and extracts the data from the given file</p>

<h2 id="zsteg">Zsteg</h2>
<p>zsteg is a tool that can detect hidden data in png and bmp files.<br>
to install it : <code class="language-plaintext highlighter-rouge">gem install zsteg</code> , The source can be found on <a href="https://github.com/zed-0xff/zsteg" target="_blank" rel="noopener noreferrer">github</a></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">zsteg -a file</code> : Runs all the methods on the given file
<br><code class="language-plaintext highlighter-rouge">zsteg -E file</code> : Extracts data from the given payload (example : zsteg -E b4,bgr,msb,xy name.png){: .align-center}<br><br></p>

<h2 id="wavsteg">Wavsteg</h2>
<p>WavSteg is a python3 tool that can hide data and files in wav files and can also extract data from wav files.<br>
You can get it from <a href="https://github.com/ragibson/Steganography#WavSteg" target="_blank" rel="noopener noreferrer">github</a></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">python3 WavSteg.py -r -s soundfile -o outputfile</code> : extracts data from a wav sound file and outputs the data into a new file</p>

<h2 id="sonic-visualizer">Sonic visualizer</h2>
<p>Sonic visualizer is a tool for viewing and analyzing the contents of audio files, however it can be helpful when dealing with audio steganography. You can reveal hidden shapes in audio files.<br>
<a href="https://www.sonicvisualiser.org/" target="_blank" rel="noopener noreferrer">Offical Website</a></p>

<h2 id="web-tools">Web Tools</h2>

<h2 id="unicode-text-steganography"><a href="https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder" target="_blank" rel="noopener noreferrer">Unicode Text Steganography</a></h2>
<p>A web tool for unicode steganography , it can encode and decode text.<br></p>

<h2 id="npiet-online"><a href="https://www.bertnase.de/npiet/npiet-execute.php" target="_blank" rel="noopener noreferrer">npiet online</a></h2>
<p>an online interpreter for piet. piet is an esoteric language , programs in piet are images. read more about piet <a href="http://www.dangermouse.net/esoteric/piet.html" target="_blank" rel="noopener noreferrer">here</a></p>

<h2 id="dcodefr"><a href="https://www.dcode.fr/" target="_blank" rel="noopener noreferrer">dcode.fr</a></h2>
<p>Sometimes when solving steganography challenges you will need to decode some text. dcode.fr has many decoders for a lot of ciphers and can be really helpful.<br></p>

<h2 id="bruteforcers">Bruteforcers</h2>

<h2 id="stegcracker"><a href="https://github.com/Paradoxis/StegCracker" target="_blank" rel="noopener noreferrer">StegCracker</a></h2>
<p>A tool that bruteforces passwords using steghide</p>

<h2 id="fcrackzip">Fcrackzip</h2>
<p>Sometimes the extracted data is a password protected zip , this tool bruteforces zip archives.<br>
It can be installed with <code class="language-plaintext highlighter-rouge">apt</code> however the <a href="https://github.com/hyc/fcrackzip" target="_blank" rel="noopener noreferrer">source</a> can be found on github.<br></p>

<p>Useful commands:
<br><code class="language-plaintext highlighter-rouge">fcrackzip -u -D -p wordlist.txt file.zip</code> : bruteforces the given zip file with passwords from the given wordlist</p>

<h2 id="challenges">Challenges</h2>
<p>Some platforms to solve stego challenges
<a href="https://www.hackthebox.eu" target="_blank" rel="noopener noreferrer">Hack The Box</a>
<a href="https://www.root-me.org" target="_blank" rel="noopener noreferrer">root me</a>
<a href="https://ringzer0ctf.com/challenges" target="_blank" rel="noopener noreferrer">RingerZeroCTF</a></p>

