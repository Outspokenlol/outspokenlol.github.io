class MusicPlayer {
    constructor() {
        this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
        this.audioElement = new Audio();
        this.audioSource = this.audioContext.createMediaElementSource(this.audioElement);
        this.gainNode = this.audioContext.createGain();
        this.analyser = this.audioContext.createAnalyser();
        
        this.audioSource.connect(this.gainNode);
        this.gainNode.connect(this.analyser);
        this.analyser.connect(this.audioContext.destination);
        
        this.songs = [];
        this.currentSongIndex = 0;
        this.isPlaying = false;
        this.volume = 0.8;
        this.isMuted = false;
        
        this.setupEventListeners();
        this.loadFromLocalStorage();
    }
    
    setupEventListeners() {
        // Play/Pause button
        document.getElementById('play-btn').addEventListener('click', () => this.togglePlay());
        
        // Previous/Next buttons
        document.getElementById('prev-btn').addEventListener('click', () => this.playPrevious());
        document.getElementById('next-btn').addEventListener('click', () => this.playNext());
        
        // Progress bar
        const progressBar = document.getElementById('progress-bar');
        progressBar.addEventListener('click', (e) => this.seek(e));
        
        // Volume control
        const volumeBar = document.getElementById('volume-bar');
        volumeBar.addEventListener('click', (e) => this.setVolume(e));
        document.getElementById('mute-btn').addEventListener('click', () => this.toggleMute());
        
        // File upload
        document.getElementById('upload-btn').addEventListener('click', () => {
            document.getElementById('file-upload').click();
        });
        document.getElementById('file-upload').addEventListener('change', (e) => this.handleFileUpload(e));
        
        // Audio element events
        this.audioElement.addEventListener('timeupdate', () => this.updateProgressBar());
        this.audioElement.addEventListener('ended', () => this.playNext());
        this.audioElement.addEventListener('loadedmetadata', () => {
            document.getElementById('duration').textContent = this.formatTime(this.audioElement.duration);
        });
    }
    
    loadFromLocalStorage() {
        const savedSongs = localStorage.getItem('sonaria-songs');
        if (savedSongs) {
            this.songs = JSON.parse(savedSongs);
            this.renderSongList();
        }
    }
    
    saveToLocalStorage() {
        localStorage.setItem('sonaria-songs', JSON.stringify(this.songs));
    }
    
    handleFileUpload(event) {
        const files = event.target.files;
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            if (file.type.startsWith('audio/')) {
                const song = {
                    id: Date.now() + i,
                    name: file.name.replace(/\.[^/.]+$/, ""), // Remove file extension
                    file: URL.createObjectURL(file),
                    artist: 'Unknown Artist'
                };
                this.songs.push(song);
            }
        }
        this.saveToLocalStorage();
        this.renderSongList();
    }
    
    renderSongList() {
        const songGrid = document.getElementById('song-grid');
        songGrid.innerHTML = '';
        
        this.songs.forEach((song, index) => {
            const songCard = document.createElement('div');
            songCard.className = 'song-card';
            songCard.innerHTML = `
                <div class="song-image">♪</div>
                <div class="song-title">${song.name}</div>
                <div class="song-artist">${song.artist}</div>
            `;
            songCard.addEventListener('click', () => this.playSong(index));
            songGrid.appendChild(songCard);
        });
    }
    
    playSong(index) {
        if (index >= 0 && index < this.songs.length) {
            this.currentSongIndex = index;
            const song = this.songs[index];
            
            this.audioElement.src = song.file;
            this.audioElement.play()
                .then(() => {
                    this.isPlaying = true;
                    document.getElementById('play-btn').textContent = '⏸';
                    document.getElementById('now-playing-title').textContent = song.name;
                    document.getElementById('now-playing-artist').textContent = song.artist;
                    
                    // Resume audio context if it was suspended
                    if (this.audioContext.state === 'suspended') {
                        this.audioContext.resume();
                    }
                })
                .catch(error => {
                    console.error('Playback failed:', error);
                });
        }
    }
    
    togglePlay() {
        if (this.songs.length === 0) return;
        
        if (this.audioElement.paused) {
            if (!this.audioElement.src) {
                this.playSong(0);
            } else {
                this.audioElement.play()
                    .then(() => {
                        this.isPlaying = true;
                        document.getElementById('play-btn').textContent = '⏸';
                    });
            }
        } else {
            this.audioElement.pause();
            this.isPlaying = false;
            document.getElementById('play-btn').textContent = '▶';
        }
    }
    
    playPrevious() {
        if (this.songs.length === 0) return;
        
        let newIndex = this.currentSongIndex - 1;
        if (newIndex < 0) {
            newIndex = this.songs.length - 1;
        }
        this.playSong(newIndex);
    }
    
    playNext() {
        if (this.songs.length === 0) return;
        
        let newIndex = this.currentSongIndex + 1;
        if (newIndex >= this.songs.length) {
            newIndex = 0;
        }
        this.playSong(newIndex);
    }
    
    seek(event) {
        if (this.songs.length === 0) return;
        
        const progressBar = document.getElementById('progress-bar');
        const rect = progressBar.getBoundingClientRect();
        const pos = (event.clientX - rect.left) / rect.width;
        this.audioElement.currentTime = pos * this.audioElement.duration;
    }
    
    setVolume(event) {
        const volumeBar = document.getElementById('volume-bar');
        const rect = volumeBar.getBoundingClientRect();
        let pos = (event.clientX - rect.left) / rect.width;
        
        // Clamp between 0 and 1
        pos = Math.max(0, Math.min(1, pos));
        
        this.volume = pos;
        this.gainNode.gain.value = pos;
        document.getElementById('volume-fill').style.width = `${pos * 100}%`;
        
        if (pos === 0) {
            this.isMuted = true;
            document.getElementById('mute-btn').textContent = '🔇';
        } else {
            this.isMuted = false;
            document.getElementById('mute-btn').textContent = '🔊';
        }
    }
    
    toggleMute() {
        this.isMuted = !this.isMuted;
        if (this.isMuted) {
            this.gainNode.gain.value = 0;
            document.getElementById('mute-btn').textContent = '🔇';
        } else {
            this.gainNode.gain.value = this.volume;
            document.getElementById('mute-btn').textContent = '🔊';
        }
    }
    
    updateProgressBar() {
        if (this.audioElement.duration) {
            const progress = (this.audioElement.currentTime / this.audioElement.duration) * 100;
            document.getElementById('progress-fill').style.width = `${progress}%`;
            document.getElementById('current-time').textContent = this.formatTime(this.audioElement.currentTime);
        }
    }
    
    formatTime(seconds) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return `${mins}:${secs < 10 ? '0' + secs : secs}`;
    }
}

// Initialize the player when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const player = new MusicPlayer();
    
    // Theme switching functionality
    const themeOptions = document.querySelectorAll('.theme-option');
    themeOptions.forEach(option => {
        option.addEventListener('click', function() {
            const theme = this.getAttribute('data-theme');
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('sonaria-theme', theme);
            
            themeOptions.forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Load saved theme
    const savedTheme = localStorage.getItem('sonaria-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    document.querySelector(`.theme-option[data-theme="${savedTheme}"]`)?.classList.add('active');
    
    // Navigation between pages
    const navButtons = document.querySelectorAll('.nav-button');
    navButtons.forEach(button => {
        button.addEventListener('click', function() {
            const page = this.getAttribute('data-page');
            if (page === 'settings') {
                window.location.href = 'settings.html';
            } else if (page === 'home' && window.location.pathname.includes('settings')) {
                window.location.href = 'index.html';
            }
            
            navButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
        });
    });
});