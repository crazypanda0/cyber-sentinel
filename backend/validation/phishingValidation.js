const {z} = require("zod");

const urlSchema = z.object({
    url : z.string().url()
});

const emailSchema = z.object({
    email : z.string().email("Invalid email format"),
    emailContent : z.string(),
})

module.exports = {urlSchema, emailSchema};