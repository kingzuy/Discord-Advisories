import 'dotenv/config';
import { Client, GatewayIntentBits, EmbedBuilder } from 'discord.js';
import fs from 'fs/promises';
import path from 'path';

class GitHubSecurityBot {
    constructor() {
        this.client = new Client({
            intents: [
                GatewayIntentBits.Guilds,
                GatewayIntentBits.GuildMessages,
                GatewayIntentBits.MessageContent
            ]
        });

        this.initializeFiles();
        this.logFile = path.join(process.cwd(), 'log.txt');
        this.channelFile = path.join(process.cwd(), 'channel.txt');
        this.setupClientEvents();
    }

    setupClientEvents() {
        this.client.on('ready', () => {
            console.log(`Logged in as ${this.client.user.tag}`);
            this.startSecurityAdvisoriesMonitoring();
        });

        this.client.on('messageCreate', async (message) => {
            if (message.content === '.setup') {
                await this.setupMonitoringChannel(message);
            }
        });
    }

    async setupMonitoringChannel(message) {
        if (!message.member.permissions.has('Administrator')) {
            return message.reply('Only administrators can set monitoring channel');
        }

        const channelId = message.channel.id;
        await fs.writeFile(this.channelFile, channelId);
        message.reply(`Channel ${channelId} set for GitHub Security Advisories monitoring`);
    }

    async startSecurityAdvisoriesMonitoring() {
        try {
            const channelId = await fs.readFile(this.channelFile, 'utf8');
            const channel = this.client.channels.cache.get(channelId);

            if (!channel) {
                console.error('Monitoring channel not found');
                return;
            }

            await this.checkSecurityAdvisories(channel);
            setInterval(async () => {
                await this.checkSecurityAdvisories(channel);
            }, 15 * 60 * 1000);
        } catch (error) {
            console.error('Monitoring setup error:', error);
        }
    }

    async checkSecurityAdvisories(channel) {
        try {
            const req = await fetch("https://api.github.com/advisories", {
                headers: {
                    "accept": "application/vnd.github+json",
                    "cache-control": "no-cache",
                    "content-type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28"
                },
                method: "GET"
            });

            const res = await req.json();
            const log = await fs.readFile(this.logFile, 'utf8');

            for (const data of res) {
                const id = data.ghsa_id;

                if (log.includes(id)) {
                    console.log(`${id} skipping...`);
                    continue;
                }

                const payload = this.generatePayload(data);
                await channel.send(payload);

                await fs.appendFile(this.logFile, `${id}\n`);
                await this.delay(5000);
            }
        } catch (error) {
            console.error('Detailed error:', error);
        }
    }

    generatePayload(data) {
        const roleId = process.env.ROLE_ID ? `<@&${process.env.ROLE_ID}>` : null;
        
        const embed = new EmbedBuilder()
            .setTitle(data.summary || 'No Summary Available')
            .setDescription(data.description || 'No Description Available')
            .setColor(this.generateEmbedColor(data.severity))
            .setURL(data.html_url || '')

        // Dynamically add fields, skipping null or undefined values
        const fields = [];

        // Vulnerable Packages
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            fields.push({
                name: "Vulnerable Packages",
                value: this.getVulnPackages(data.vulnerabilities),
                inline: false
            });
        }

        // Severity
        fields.push({
            name: "Severity",
            value: this.getSeverityIcon(data.severity || 'unknown'),
            inline: true
        });

        // CVSS Score
        fields.push({
            name: "CVSS Score",
            value: data.cvss?.score?.toString() || 'N/A',
            inline: true
        });

        // References
        if (data.references && data.references.length > 0) {
            fields.push({
                name: "References",
                value: this.getReferences(data.references),
                inline: false
            });
        }

        // GHSA ID
        fields.push({
            name: "GHSA ID",
            value: data.ghsa_id || 'N/A',
            inline: true
        });

        // CVE ID
        fields.push({
            name: "CVE ID",
            value: data.cve_id || 'N/A',
            inline: true
        });

        // Add fields to embed
        embed.addFields(fields);

        // Set author if source code location is available
        if (data.source_code_location) {
            embed.setAuthor({
                name: data.source_code_location.replace('https://github.com/', ''),
                url: data.source_code_location,
                iconURL: data.source_code_location.replace(/\/[^\/]+$/, '.png')
            });
        }

        // Set footer
        embed.setFooter({
            text: "GitHub Security Advisory Bot",
            iconURL: "https://github.com/github.png"
        });

        return {
            content: roleId,
            embeds: [embed]
        };
    }

    generateEmbedColor(severity) {
        const colors = {
            'low': 0x78a354,
            'medium': 0xfcc624,
            'high': 0xff6b4c,
            'critical': 0xdd4c4c
        };
        return colors[severity] || 0xE0E0E0;
    }

    getSeverityIcon(severity) {
        const icons = {
            'low': ':green_circle: Low',
            'medium': ':yellow_circle: Medium',
            'high': ':orange_circle: High',
            'critical': ':red_circle: Critical'
        };
        return icons[severity] || '-';
    }

    getVulnPackages(vulnerabilities) {
        return vulnerabilities.map((vuln, i) => {
            const pkg = vuln.package;
            return `* \`${pkg?.name || 'Unknown Package'}\` (${pkg?.ecosystem || 'Unknown'}) version \`${vuln.vulnerable_version_range || 'N/A'}\`` +
                (i < vulnerabilities.length - 1 ? '\n' : '');
        }).join('');
    }

    getReferences(references) {
        return references.map((ref, i) => {
            return `* ${ref || 'N/A'}` + (i < references.length - 1 ? '\n' : '');
        }).join('');
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async initializeFiles() {
        try {
            await fs.access(this.logFile);
        } catch (error) {
            await fs.writeFile(this.logFile, '');
            console.log('Log file created');
        }

        try {
            await fs.access(this.channelFile);
        } catch (error) {
            console.log('Channel file not found. Please use .setup command to set monitoring channel');
        }
    }

    async start() {
        await this.client.login(process.env.DISCORD_BOT_TOKEN);
    }
}

const bot = new GitHubSecurityBot();
bot.start();