<template>
    <div class="content-view">
        <div v-if="content_view == 'content-status'">
            <content_status></content_status>
        </div>
        <div v-else-if="content_view == 'content-configuration'">
            <content_configuration></content_configuration>
        </div>
        <div v-else>
            this is from Content, content_view is {{ content_view }}
        </div>
    </div>
</template>
<script>
    import content_status from './content/status'
    import content_configuration from './content/configuration'

    export default {
        props: ['content_view'],
        components: {
            content_status,
            content_configuration
        }
    }
</script>
