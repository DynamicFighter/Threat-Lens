const canvas = document.getElementById("networkCanvas");
const ctx = canvas.getContext("2d");

let particles = [];

function resizeCanvas() {

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    createParticles();
}


function createParticles() {

    particles = [];

    const amount = Math.min(
        90,
        Math.floor(window.innerWidth / 15)
    );

    for (let i = 0; i < amount; i++) {

        particles.push({

            x: Math.random() * canvas.width,

            y: Math.random() * canvas.height,

            vx: (Math.random() - 0.5) * 0.35,

            vy: (Math.random() - 0.5) * 0.35,

            size: Math.random() * 1.5 + 0.5

        });
    }
}


function drawParticles() {

    ctx.clearRect(
        0,
        0,
        canvas.width,
        canvas.height
    );


    /* Move particles */

    particles.forEach(particle => {

        particle.x += particle.vx;
        particle.y += particle.vy;


        /* Wrap around screen */

        if (particle.x < 0)
            particle.x = canvas.width;

        if (particle.x > canvas.width)
            particle.x = 0;

        if (particle.y < 0)
            particle.y = canvas.height;

        if (particle.y > canvas.height)
            particle.y = 0;


        /* Draw dot */

        ctx.beginPath();

        ctx.arc(
            particle.x,
            particle.y,
            particle.size,
            0,
            Math.PI * 2
        );

        ctx.fillStyle = "rgba(80,180,255,0.55)";

        ctx.fill();

    });


    /* Draw connections */

    for (let i = 0; i < particles.length; i++) {

        for (let j = i + 1; j < particles.length; j++) {

            const dx =
                particles[i].x -
                particles[j].x;

            const dy =
                particles[i].y -
                particles[j].y;

            const distance =
                Math.sqrt(dx * dx + dy * dy);


            if (distance < 120) {

                const opacity =
                    0.12 *
                    (1 - distance / 120);


                ctx.beginPath();

                ctx.moveTo(
                    particles[i].x,
                    particles[i].y
                );

                ctx.lineTo(
                    particles[j].x,
                    particles[j].y
                );

                ctx.strokeStyle =
                    `rgba(50,150,230,${opacity})`;

                ctx.lineWidth = 0.5;

                ctx.stroke();
            }
        }
    }


    requestAnimationFrame(drawParticles);
}


window.addEventListener(
    "resize",
    resizeCanvas
);


resizeCanvas();

drawParticles();