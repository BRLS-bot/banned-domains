const urlJson = require('./json.json');

interface res {
    phishingLink: string | null;
    present: boolean;
    susp: boolean;
}

export function scan(content: string): Promise<res> {
    return new Promise(resolve => {
        let present = []
        for(let i = 0; i < urlJson.domains.length; i++) {
            let url = urlJson.domains[i];
            if(content.includes(url)) {
                present.push(url);
                break;
            }
        }

        let present2 = []
        for(let y = 0; y < urlJson.sus.length; y++) {
            let url = urlJson.sus[y];
            if(content.includes(url)) {
                present2.push(url);
                break;
            }
        }

        if(present.length == 1) {
            let result = {
                phishingLink: present[0],
                present: true,
                susp: true
            }
            resolve(result);
        } else {
            resolve({
                phishingLink: present2[0] || null,
                present: false,
                susp: present2.length > 0
            });
        }
    })
}
