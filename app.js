// Discord Webhook URL provided by the user
const WEBHOOK_URL = "https://discord.com/api/webhooks/1522031187659456635/nesbA0q4ahCBY4c4GGBQrtVyIb7fz34QDxNisj0orTy-CVy0nXvLR2xqRMdXwnrVAKZJ";

document.getElementById('applicationForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const form = this;
    const submitBtn = document.getElementById('submitBtn');
    const btnText = document.querySelector('.btn-text');
    const loader = document.getElementById('submitLoader');
    const successMsg = document.getElementById('successMessage');
    const errorMsg = document.getElementById('errorMessage');

    // Reset messages
    successMsg.style.display = 'none';
    errorMsg.style.display = 'none';

    // UI Loading state
    submitBtn.disabled = true;
    btnText.style.display = 'none';
    loader.style.display = 'block';

    // Collect data
    const formData = new FormData(form);
    
    // Create the Discord Embed payload
    const payload = {
        username: "Staff Application Bot",
        avatar_url: "https://i.imgur.com/4M34hiw.png", // Generic bot avatar
        embeds: [{
            title: "📝 New Staff Application",
            color: 7031265, // A nice purple matching the site theme
            fields: [
                {
                    name: "1. Minecraft Username",
                    value: formData.get('username') || "N/A",
                    inline: true
                },
                {
                    name: "2. Position Seeking",
                    value: formData.get('position') || "N/A",
                    inline: true
                },
                {
                    name: "3. Age & Timezone",
                    value: formData.get('ageTimezone') || "N/A",
                    inline: true
                },
                {
                    name: "4. Daily Playtime",
                    value: formData.get('playtime') || "N/A"
                },
                {
                    name: "5. Server Improvements",
                    value: formData.get('improvement') || "N/A"
                },
                {
                    name: "6. Previous Experience",
                    value: formData.get('experience') || "N/A"
                },
                {
                    name: "7. Why choose you?",
                    value: formData.get('whyYou') || "N/A"
                },
                {
                    name: "8. Scenario: Billy vs John (Argument)",
                    value: formData.get('scenario1') || "N/A"
                },
                {
                    name: "9. Scenario: Missing Donation Rank",
                    value: formData.get('scenario2') || "N/A"
                },
                {
                    name: "10. Scenario: Chat Spammer",
                    value: formData.get('scenario3') || "N/A"
                },
                {
                    name: "11. About Yourself",
                    value: formData.get('about') || "N/A"
                }
            ],
            footer: {
                text: "Submitted via Website • " + new Date().toLocaleString()
            }
        }]
    };

    try {
        const response = await fetch(WEBHOOK_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            // Success
            successMsg.style.display = 'block';
            form.reset();
        } else {
            // Discord rejected it (e.g. rate limit, or field too long)
            console.error('Discord API Error:', response.status, response.statusText);
            errorMsg.style.display = 'block';
        }
    } catch (error) {
        console.error('Network Error:', error);
        errorMsg.style.display = 'block';
    } finally {
        // Reset UI
        submitBtn.disabled = false;
        btnText.style.display = 'block';
        loader.style.display = 'none';
    }
});
