<template>
    <div>
        <div class="logo"></div>
        <div class="header-right">
            this is from Header, data is {{ data }}
            <Button size="large" type="primary" @click="handler">Header Button</Button>
        </div>
    </div>
</template>
<script>
    export default {
        props: ['data'],
        methods: {
            handler () {
                this.$emit('set_sider_data', 'sider data from header');
                this.$emit('set_content_data', 'content data from header');
                this.$Modal.info({
                    title: 'nihao title',
                    content: 'nihao haha'
                });
            }
        }
    }
</script>
